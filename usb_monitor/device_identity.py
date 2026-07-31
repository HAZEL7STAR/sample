"""
device_identity.py

Builds a stable identity fingerprint for a USB device from udev properties.
If ANY identity field changes, the device is treated as a different device
(per project spec) — enforced by comparing the full tuple, not just serial.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class DeviceIdentity:
    vendor_id: str
    product_id: str
    serial_number: str
    manufacturer: str
    device_name: str
    filesystem: Optional[str]
    capacity_bytes: Optional[int]
    bus_number: Optional[str]
    device_number: Optional[str]
    device_node: str  # e.g. /dev/sdb1
    usb_version: Optional[str] = None

    @property
    def fingerprint(self) -> str:
        """Stable hash identity used as the DB unique key for a physical device."""
        raw = "|".join([
            self.vendor_id or "",
            self.product_id or "",
            self.serial_number or "",
            self.manufacturer or "",
            self.device_name or "",
        ])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


def build_identity_from_udev(device) -> Optional[DeviceIdentity]:
    """
    device: a pyudev.Device (a partition/filesystem-level device, i.e. subsystem 'block',
    devtype 'partition', with ID_BUS == 'usb').
    Returns None if this isn't a USB block device we care about.
    """
    if device.get("ID_BUS") != "usb":
        return None

    parent = device.find_parent("usb", "usb_device")
    vendor_id = device.get("ID_VENDOR_ID") or (parent.get("idVendor") if parent else None)
    product_id = device.get("ID_MODEL_ID") or (parent.get("idProduct") if parent else None)
    serial = device.get("ID_SERIAL_SHORT") or device.get("ID_SERIAL")
    manufacturer = device.get("ID_VENDOR") or (parent.get("manufacturer") if parent else "Unknown")
    name = device.get("ID_MODEL") or (parent.get("product") if parent else "Unknown USB Device")
    fs = device.get("ID_FS_TYPE")

    capacity = None
    try:
        size_attr = device.attributes.get("size")
        if size_attr:
            # size is in 512-byte sectors
            capacity = int(size_attr) * 512
    except Exception:
        capacity = None

    usb_version = None
    if parent is not None:
        usb_version = parent.get("version")

    return DeviceIdentity(
        vendor_id=vendor_id or "UNKNOWN",
        product_id=product_id or "UNKNOWN",
        serial_number=serial or "UNKNOWN",
        manufacturer=manufacturer or "Unknown",
        device_name=name or "Unknown USB Device",
        filesystem=fs,
        capacity_bytes=capacity,
        bus_number=device.get("ID_PATH"),
        device_number=device.sys_number if hasattr(device, "sys_number") else None,
        device_node=device.device_node or "",
        usb_version=usb_version,
    )
