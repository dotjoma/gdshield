extends Control

@onready var status_label: Label = $VBoxContainer/StatusLabel
@onready var audit_button: Button = $VBoxContainer/AuditButton

func _ready() -> void:
	# 1. Mount hardened game data pack if present (Offset 512 + Magic MMOR)
	_mount_hardened_pack()

func _mount_hardened_pack() -> void:
	var exe_dir: String = OS.get_executable_path().get_base_dir()
	var pack_path: String = exe_dir.path_join("game_data.pck")
	
	if FileAccess.file_exists(pack_path):
		var ok: bool = ProjectSettings.load_resource_pack(pack_path, true, GDShieldRuntime.PACK_OFFSET)
		if ok:
			status_label.text = "Status: Protected Pack Mounted (Offset: %d, Magic: %s)" % [GDShieldRuntime.PACK_OFFSET, GDShieldRuntime.PACK_MAGIC]
			print("[GDShield Demo] Hardened pack mounted successfully at offset %d." % GDShieldRuntime.PACK_OFFSET)
		else:
			status_label.text = "Status: Error Mounting Hardened Pack"
			push_error("[GDShield Demo] Failed to mount: " + pack_path)
	else:
		status_label.text = "Status: Running in Development Mode (res:// local resources)"
		print("[GDShield Demo] No game_data.pck found; running with local project assets.")

func _on_audit_button_pressed() -> void:
	var root_dir: String = ProjectSettings.globalize_path("res://")
	var script_path: String = root_dir.path_join("tools/gdshield/gdshield.py")
	status_label.text = "Running gdshield security self-audit..."
	
	var output: Array = []
	var code: int = OS.execute("python", [script_path, "audit", "--dir", root_dir], output, true)
	print("".join(output))
	
	if code == 0:
		status_label.text = "Audit Result: PASS (0 Vulnerabilities Found)"
	else:
		status_label.text = "Audit Result: Review audit_report.txt"
