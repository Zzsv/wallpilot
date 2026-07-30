from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable


def _unwrap(value: Any) -> Any:
    if hasattr(value, "value"):
        return _unwrap(value.value)
    if isinstance(value, dict):
        return {str(key): _unwrap(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_unwrap(item) for item in value]
    return value


class FirewalldDBus:
    """Small synchronous facade over firewalld's official system D-Bus API."""

    service = "org.fedoraproject.FirewallD1"
    root_path = "/org/fedoraproject/FirewallD1"
    config_path = "/org/fedoraproject/FirewallD1/config"

    @staticmethod
    def _run(factory: Callable[[], Awaitable[Any]]) -> Any:
        return asyncio.run(factory())

    async def _connect(self) -> Any:
        try:
            from dbus_next.aio import MessageBus
            from dbus_next.constants import BusType
        except ImportError as exc:
            raise RuntimeError("缺少 dbus-next，无法使用 firewalld D-Bus") from exc
        return await MessageBus(bus_type=BusType.SYSTEM).connect()

    async def _root_interfaces(self) -> tuple[Any, Any, Any]:
        bus = await self._connect()
        introspection = await bus.introspect(self.service, self.root_path)
        obj = bus.get_proxy_object(self.service, self.root_path, introspection)
        main = obj.get_interface("org.fedoraproject.FirewallD1")
        zone = obj.get_interface("org.fedoraproject.FirewallD1.zone")
        return bus, main, zone

    async def _config_zone(self, zone_name: str) -> tuple[Any, Any]:
        bus = await self._connect()
        config_intro = await bus.introspect(self.service, self.config_path)
        config_obj = bus.get_proxy_object(self.service, self.config_path, config_intro)
        config = config_obj.get_interface("org.fedoraproject.FirewallD1.config")
        path = await config.call_get_zone_by_name(zone_name)
        zone_intro = await bus.introspect(self.service, path)
        zone_obj = bus.get_proxy_object(self.service, path, zone_intro)
        zone = zone_obj.get_interface("org.fedoraproject.FirewallD1.config.zone")
        return bus, zone

    async def _default_zone_async(self) -> str:
        bus, main, _zone = await self._root_interfaces()
        try:
            return str(await main.call_get_default_zone())
        finally:
            bus.disconnect()

    def default_zone(self) -> str:
        return self._run(self._default_zone_async)

    async def _snapshot_async(self) -> dict[str, Any]:
        bus, main, zone_iface = await self._root_interfaces()
        try:
            default_zone = str(await main.call_get_default_zone())
            active = _unwrap(await zone_iface.call_get_active_zones())
            zone_names = set(active.keys())
            zone_names.add(default_zone)
            try:
                zone_names.update(_unwrap(await zone_iface.call_get_zones()))
            except Exception:
                pass
            zones: dict[str, dict[str, Any]] = {}
            for name in sorted(zone_names):
                settings: dict[str, Any]
                try:
                    settings = _unwrap(await zone_iface.call_get_zone_settings2(name))
                except Exception:
                    raw = _unwrap(await zone_iface.call_get_zone_settings(name))
                    settings = self._tuple_settings(raw)
                zones[name] = self._normalize_settings(settings)
            return {
                "default_zone": default_zone,
                "active_zones": active,
                "zones": zones,
            }
        finally:
            bus.disconnect()

    def snapshot(self) -> dict[str, Any]:
        return self._run(self._snapshot_async)

    async def _reload_async(self) -> None:
        bus, main, _zone = await self._root_interfaces()
        try:
            await main.call_reload()
        finally:
            bus.disconnect()

    def reload(self) -> None:
        self._run(self._reload_async)

    @staticmethod
    def _tuple_settings(raw: Any) -> dict[str, Any]:
        if not isinstance(raw, list):
            return {}
        keys = (
            "version",
            "short",
            "description",
            "unused",
            "target",
            "services",
            "ports",
            "icmp_blocks",
            "masquerade",
            "forward_ports",
            "interfaces",
            "sources",
            "rich_rules",
            "protocols",
            "source_ports",
            "icmp_block_inversion",
        )
        return {key: raw[index] for index, key in enumerate(keys) if index < len(raw)}

    @staticmethod
    def _normalize_settings(settings: dict[str, Any]) -> dict[str, Any]:
        aliases = {
            "richRules": "rich_rules",
            "icmpBlocks": "icmp_blocks",
            "forwardPorts": "forward_ports",
            "sourcePorts": "source_ports",
            "icmpBlockInversion": "icmp_block_inversion",
        }
        normalized: dict[str, Any] = {}
        for key, value in settings.items():
            normalized[aliases.get(key, key)] = _unwrap(value)
        for key in (
            "services",
            "ports",
            "icmp_blocks",
            "forward_ports",
            "interfaces",
            "sources",
            "rich_rules",
            "protocols",
            "source_ports",
        ):
            normalized.setdefault(key, [])
        return normalized

    async def _runtime_change(
        self,
        method: str,
        zone_name: str,
        args: tuple[Any, ...],
        timeout: int,
    ) -> None:
        bus, _main, zone = await self._root_interfaces()
        try:
            call = getattr(zone, f"call_{method}")
            await call(zone_name, *args, timeout)
        finally:
            bus.disconnect()

    async def _permanent_change(
        self,
        method: str,
        zone_name: str,
        args: tuple[Any, ...],
    ) -> None:
        bus, zone = await self._config_zone(zone_name)
        try:
            call = getattr(zone, f"call_{method}")
            await call(*args)
        finally:
            bus.disconnect()

    def _change(
        self,
        kind: str,
        zone_name: str,
        args: tuple[Any, ...],
        operation: str,
        permanent: bool,
        timeout: int,
    ) -> None:
        if operation not in {"add", "remove"}:
            raise ValueError("unsupported firewalld operation")
        method = f"{operation}_{kind}"
        if permanent:
            self._run(lambda: self._permanent_change(method, zone_name, args))
        else:
            self._run(lambda: self._runtime_change(method, zone_name, args, timeout))

    def change_port(
        self,
        zone_name: str,
        port: str,
        protocol: str,
        operation: str,
        permanent: bool,
        timeout: int = 0,
    ) -> None:
        self._change("port", zone_name, (port, protocol), operation, permanent, timeout)

    def change_service(
        self,
        zone_name: str,
        service: str,
        operation: str,
        permanent: bool,
        timeout: int = 0,
    ) -> None:
        self._change("service", zone_name, (service,), operation, permanent, timeout)

    def change_rich_rule(
        self,
        zone_name: str,
        rule: str,
        operation: str,
        permanent: bool,
        timeout: int = 0,
    ) -> None:
        self._change("rich_rule", zone_name, (rule,), operation, permanent, timeout)

    def change_source(
        self,
        zone_name: str,
        source: str,
        operation: str,
        permanent: bool,
        timeout: int = 0,
    ) -> None:
        self._change("source", zone_name, (source,), operation, permanent, timeout)

    def change_protocol(
        self,
        zone_name: str,
        protocol: str,
        operation: str,
        permanent: bool,
        timeout: int = 0,
    ) -> None:
        self._change("protocol", zone_name, (protocol,), operation, permanent, timeout)

    def change_source_port(
        self,
        zone_name: str,
        port: str,
        protocol: str,
        operation: str,
        permanent: bool,
        timeout: int = 0,
    ) -> None:
        self._change(
            "source_port", zone_name, (port, protocol), operation, permanent, timeout
        )

    def change_icmp_block(
        self,
        zone_name: str,
        icmp_type: str,
        operation: str,
        permanent: bool,
        timeout: int = 0,
    ) -> None:
        self._change(
            "icmp_block", zone_name, (icmp_type,), operation, permanent, timeout
        )

    def change_masquerade(
        self,
        zone_name: str,
        operation: str,
        permanent: bool,
        timeout: int = 0,
    ) -> None:
        self._change("masquerade", zone_name, (), operation, permanent, timeout)

    def change_forward_port(
        self,
        zone_name: str,
        port: str,
        protocol: str,
        to_port: str,
        to_address: str,
        operation: str,
        permanent: bool,
        timeout: int = 0,
    ) -> None:
        self._change(
            "forward_port",
            zone_name,
            (port, protocol, to_port, to_address),
            operation,
            permanent,
            timeout,
        )
