import re
from typing import Dict, List, Any, Tuple, Optional
from core.config import logger

class VulnerabilityValidator:
    """
    Enforces Golden Rule #4:
    Never treat 'Wazuh Active' as the sole proof of patch failure.
    Cross-reference with Syscollector Hotfix Inventory and OS Build Number.
    Windows Cumulative Updates (LCU) supersede all previous monthly KBs.
    """

    STATUS_CONFIRMED_VULNERABLE = "CONFIRMED_VULNERABLE"
    STATUS_REMEDIATED_PENDING_RESCAN = "REMEDIATED_PENDING_WAZUH_RESCAN"
    STATUS_SUPERSEDED = "SUPERSEDED_OR_MITIGATED"
    STATUS_SOLVED = "SOLVED"

    @staticmethod
    def _is_build_greater_or_equal(current_build: str, required_build: str) -> bool:
        """
        Compare Windows OS Build strings like '17763.9245' >= '17763.6054'
        """
        try:
            def parse_build(value):
                value = str(value).strip()
                if not re.fullmatch(r'\d+(?:\.\d+){1,3}', value):
                    return []
                parts = [int(p) for p in value.split('.')]
                return parts[2:] if len(parts) == 4 and parts[:2] == [10, 0] else parts
            c_nums = parse_build(current_build)
            r_nums = parse_build(required_build)
            if not c_nums or not r_nums:
                return False
            # If same major build (e.g. 17763 == 17763), compare revision (9245 >= 6054)
            if c_nums[0] == r_nums[0]:
                c_ubr = c_nums[1] if len(c_nums) > 1 else 0
                r_ubr = r_nums[1] if len(r_nums) > 1 else 0
                return c_ubr >= r_ubr
            # If newer major release (e.g. 20348 > 17763)
            return False  # Different Windows servicing branches are not interchangeable.
        except Exception:
            return False

    @classmethod
    def validate_vulnerability(
        cls,
        vuln: Dict[str, Any],
        installed_hotfixes: List[str],
        os_info: Dict[str, Any],
        expected_kb: str = None,
        min_build: str = None,
        is_server_reboot: bool = False,
        server_reboot_note: str = ""
    ) -> Dict[str, Any]:
        """
        Cross-validates an individual vulnerability against host state.

        :param vuln: Vulnerability record from Wazuh API
        :param installed_hotfixes: List of installed KB numbers (e.g. ['KB5122876', 'KB5040437'])
        :param os_info: OS build dictionary {'build': '17763.9245', 'os_name': 'Windows Server 2019'}
        :param expected_kb: Mapped KB that patches this CVE
        :param min_build: Minimum fixed OS build revision for this CVE
        :param is_server_reboot: True only if host completed installation and requested a reboot
        :param server_reboot_note: Specific note about what was installed
        """
        cve_id = vuln.get("cve", "")
        wazuh_status = (vuln.get("wazuh_status") or vuln.get("status") or "ACTIVE").upper()
        vuln_title = vuln.get("title", "")
        vuln_severity = vuln.get("severity", "Medium")

        # Normalize installed KBs to uppercase strings without spaces
        clean_hotfixes = [str(kb).strip().upper() for kb in installed_hotfixes if kb]

        # Already marked Solved in Wazuh
        if wazuh_status == "SOLVED":
            return {
                "cve": cve_id,
                "status": cls.STATUS_SOLVED,
                "reason": "Wazuh vulnerability database confirms issue is Solved.",
                "action_required": False
            }

        # 1. Check if the specific KB was installed directly
        if expected_kb:
            norm_expected_kb = expected_kb.strip().upper()
            if norm_expected_kb in clean_hotfixes:
                current_build = os_info.get("build") if os_info else ""
                has_fixed_build = bool(min_build and current_build and cls._is_build_greater_or_equal(current_build, min_build))

                if has_fixed_build:
                    logger.info(f"Rule #4 Match: {cve_id} is ACTIVE in Wazuh, but {norm_expected_kb} is installed and verified by OS Build {current_build} >= {min_build}.")
                    return {
                        "cve": cve_id,
                        "status": cls.STATUS_REMEDIATED_PENDING_RESCAN,
                        "reason": f"KB {norm_expected_kb} đã cài đặt thành công và OS Build ({current_build}) đã đáp ứng. Wazuh đang chờ chu kỳ cập nhật inventory.",
                        "action_required": False,
                        "reboot_required": False,
                        "recommended_action": "Bản vá đã có hiệu lực. Chờ chu kỳ quét Wazuh tiếp theo hoặc quét lại agent."
                    }
                elif is_server_reboot:
                    logger.info(f"Rule #4 Match: {cve_id} has {norm_expected_kb} installed/staged, waiting for host reboot.")
                    return {
                        "cve": cve_id,
                        "status": cls.STATUS_CONFIRMED_VULNERABLE,
                        "reason": f"Bản vá {norm_expected_kb} đã được cài đặt trên máy chủ qua WSUS. {server_reboot_note or 'Đang chờ khởi động lại máy chủ (Pending Restart) để hoàn tất kích hoạt.'}",
                        "action_required": True,
                        "reboot_required": True,
                        "recommended_action": f"Khởi động lại (Restart) máy chủ để hoàn tất kích hoạt bản vá {norm_expected_kb}."
                    }
                else:
                    # Staged or downloaded by WSUS / Windows Update, but NOT installed yet (waiting for 'Install now' / installation trigger)
                    logger.info(f"WSUS Staged/Ready: {norm_expected_kb} present in inventory, but host build {current_build} < {min_build} and no reboot pending.")
                    return {
                        "cve": cve_id,
                        "status": cls.STATUS_CONFIRMED_VULNERABLE,
                        "reason": f"Bản vá {norm_expected_kb} đã được WSUS phê duyệt và đẩy về máy chủ (gói đã tải về sẵn sàng cài đặt - Updates ready to install). Cần thực hiện Cài đặt ngay (Install now) trên máy chủ.",
                        "action_required": True,
                        "reboot_required": False,
                        "recommended_action": f"Kích hoạt cài đặt bản vá {norm_expected_kb} trên máy chủ (bấm 'Install now' hoặc Trigger Install)."
                    }

        # 2. Check if Cumulative Update (LCU) covers the OS build
        # Windows cumulative updates supersede and contain all previous security fixes
        current_build = os_info.get("build") if os_info else ""
        if min_build and current_build:
            if cls._is_build_greater_or_equal(current_build, min_build):
                logger.info(f"Rule #4 Match (LCU Supersedence): {cve_id} fixed on OS Build {current_build} >= {min_build}.")
                return {
                    "cve": cve_id,
                    "status": cls.STATUS_REMEDIATED_PENDING_RESCAN,
                    "reason": f"OS Kernel Build {current_build} đã bao gồm bản vá {expected_kb or 'LCU'} (yêu cầu tối thiểu: {min_build}). Bản vá tích lũy (Cumulative Update) đã khắc phục lỗ hổng này.",
                    "action_required": False,
                    "recommended_action": "Đã vá thành công qua Bản vá tích lũy mới hơn. Chờ Wazuh đồng bộ lại cơ sở dữ liệu lỗ hổng."
                }

        # 3. Non-KB / 3rd-Party Application Vulnerability (e.g. WinRAR, Chrome, Moniker Link)
        if not expected_kb:
            return {
                "cve": cve_id,
                "status": cls.STATUS_CONFIRMED_VULNERABLE,
                "reason": "Lỗ hổng thuộc phần mềm ứng dụng (Non-OS KB / Tầng ứng dụng), không phát hành qua gói Windows Cumulative Update của WSUS. Cần nâng cấp trực tiếp phần mềm lên phiên bản an toàn, gỡ bỏ ứng dụng không dùng hoặc bấm [Dự đoán & Khắc phục qua AI] để áp dụng biện pháp cô lập.",
                "action_required": True,
                "recommended_action": "Cập nhật trực tiếp phiên bản phần mềm hoặc đăng ký Ngoại lệ (Exception) theo hướng dẫn của AI."
            }

        # 4. Confirmed Vulnerable OS Patch
        return {
            "cve": cve_id,
            "status": cls.STATUS_CONFIRMED_VULNERABLE,
            "reason": f"Bản vá dự kiến ({expected_kb}) chưa tìm thấy trên máy chủ và OS Build ({current_build or 'N/A'}) thấp hơn bản vá ({min_build or 'N/A'}).",
            "action_required": True,
            "recommended_action": f"Phê duyệt và triển khai bản vá {expected_kb} qua WSUS theo kế hoạch."
        }

    @classmethod
    def audit_agent(
        cls,
        agent_id: str,
        agent_name: str,
        vulnerabilities: List[Dict[str, Any]],
        hotfixes: List[Dict[str, Any]],
        os_info: Optional[Dict[str, Any]],
        cve_mapper,
        agent_ip: str = ""
    ) -> Dict[str, Any]:
        """
        Performs complete cross-validation for a specific agent.
        """
        installed_kb_list = []
        for h in hotfixes:
            kb_val = h.get("hotfix") or h.get("name") or h.get("description", "")
            if kb_val:
                installed_kb_list.append(str(kb_val).upper())

        os_name = ""
        os_build = ""
        if os_info:
            inner_os = os_info.get("os") if isinstance(os_info.get("os"), dict) else os_info
            os_name = inner_os.get("name") or inner_os.get("os_name", "")
            os_build = str(inner_os.get("build") or inner_os.get("os_build", ""))

        validated_vulns = []
        counts = {
            "total": len(vulnerabilities),
            "confirmed_vulnerable": 0,
            "remediated_pending_rescan": 0,
            "solved": 0,
            "critical_confirmed": 0,
            "high_confirmed": 0
        }

        # Check explicit reboot status from config/reboot_status.json
        from core.config import BASE_DIR
        reboot_file = BASE_DIR / "config" / "reboot_status.json"
        is_server_reboot = False
        server_reboot_note = ""
        if reboot_file.exists():
            try:
                import json
                with open(reboot_file, "r", encoding="utf-8") as rf:
                    rdata = json.load(rf)
                    aid_str = str(agent_id)
                    if aid_str in rdata:
                        is_server_reboot = bool(rdata[aid_str].get("reboot_pending", False))
                        server_reboot_note = rdata[aid_str].get("reboot_reasons", "")
            except Exception:
                pass

        for v in vulnerabilities:
            cve_id = v.get("cve", "")
            mapping = cve_mapper.resolve_cve(cve_id, product_name=os_name)
            expected_kb = mapping.get("kb")
            min_build = mapping.get("min_build")

            validation = cls.validate_vulnerability(
                vuln=v,
                installed_hotfixes=installed_kb_list,
                os_info={"build": os_build, "os_name": os_name},
                expected_kb=expected_kb,
                min_build=min_build,
                is_server_reboot=is_server_reboot,
                server_reboot_note=server_reboot_note
            )

            validation["wazuh_status"] = v.get("wazuh_status", v.get("status", "ACTIVE"))
            validation["severity"] = v.get("severity", "Medium")
            validation["cvss"] = v.get("cvss", 0.0)
            validation["title"] = mapping.get("title", v.get("title", ""))
            validation["expected_kb"] = expected_kb
            validation["min_build"] = min_build
            validation["published_date"] = v.get("published", v.get("published_date", ""))

            status = validation["status"]

            # If host is marked pending reboot (e.g. user installed update and waiting for restart):
            # Only OS-level patches with expected_kb are resolved by the Windows update reboot
            if status == cls.STATUS_CONFIRMED_VULNERABLE and is_server_reboot and expected_kb:
                status = cls.STATUS_REMEDIATED_PENDING_RESCAN
                validation["status"] = cls.STATUS_REMEDIATED_PENDING_RESCAN
                validation["reboot_required"] = True
                validation["action_required"] = False
                validation["reason"] = f"Bản vá {expected_kb} đã được cài đặt trên máy chủ qua WSUS. {server_reboot_note or 'Đang chờ khởi động lại máy chủ (Pending Restart) để hoàn tất cập nhật vào hệ điều hành.'}"
                validation["recommended_action"] = f"Khởi động lại (Restart) máy chủ để hoàn tất kích hoạt bản vá {expected_kb}."

            if status == cls.STATUS_CONFIRMED_VULNERABLE:
                counts["confirmed_vulnerable"] += 1
                if validation["severity"].upper() == "CRITICAL":
                    counts["critical_confirmed"] += 1
                elif validation["severity"].upper() == "HIGH":
                    counts["high_confirmed"] += 1
            elif status in (cls.STATUS_REMEDIATED_PENDING_RESCAN, cls.STATUS_SUPERSEDED):
                counts["remediated_pending_rescan"] += 1
            elif status == cls.STATUS_SOLVED:
                counts["solved"] += 1

            validated_vulns.append(validation)

        # Compute missing KBs (only those genuinely vulnerable and needing KB)
        missing_kbs = sorted(list(set(
            v.get("expected_kb") for v in validated_vulns
            if v.get("status") == cls.STATUS_CONFIRMED_VULNERABLE and v.get("expected_kb")
        )))

        # Check if ANY vulnerability genuinely requires a reboot
        needs_reboot = any(v.get("reboot_required") for v in validated_vulns)

        # If the server was marked reboot_pending, but the OS build now satisfies the updates:
        mapped_vulns = [v for v in validated_vulns if v.get("expected_kb")]
        build_verified = bool(mapped_vulns) and all(
            v.get("min_build") and cls._is_build_greater_or_equal(os_build, v["min_build"])
            for v in mapped_vulns
        )
        if is_server_reboot and not needs_reboot and build_verified:
            is_server_reboot = False
            logger.info(f"Auto-cleared reboot_pending for {agent_name} (ID: {agent_id}) - Host build {os_build} satisfies all installed KBs.")
            if reboot_file.exists() and str(agent_id) in rdata:
                try:
                    rdata[str(agent_id)]["reboot_pending"] = False
                    rdata[str(agent_id)]["reboot_reasons"] = ""
                    with open(reboot_file, "w", encoding="utf-8") as rf:
                        json.dump(rdata, rf, indent=2, ensure_ascii=False)
                except Exception as e:
                    logger.error(f"Error updating reboot_status.json: {e}")

        # Compute pending reboot flag
        reboot_pending = is_server_reboot or needs_reboot
        reboot_reasons = []
        if is_server_reboot and server_reboot_note:
            reboot_reasons.append(server_reboot_note)
        for v in validated_vulns:
            if v.get("reboot_required"):
                kb = v.get("expected_kb", "Bản vá")
                note = f"Đã cài {kb} - Cần Reboot máy chủ"
                if note not in reboot_reasons:
                    reboot_reasons.append(note)

        return {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "ip": agent_ip,
            "os_name": os_name,
            "os_build": os_build,
            "installed_hotfix_count": len(installed_kb_list),
            "installed_hotfixes": installed_kb_list,
            "missing_kbs": missing_kbs,
            "reboot_pending": reboot_pending,
            "reboot_reasons": "; ".join(sorted(list(set(reboot_reasons)))) if reboot_reasons else "",
            "summary": counts,
            "vulnerabilities": validated_vulns
        }
