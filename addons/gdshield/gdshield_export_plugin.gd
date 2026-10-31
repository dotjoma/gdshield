@tool
extends EditorExportPlugin

var _export_path: String = ""

func _get_name() -> String:
	return "gdshield"

func _export_begin(features: PackedStringArray, is_debug: bool, path: String, flags: int) -> void:
	_export_path = path

func _export_end() -> void:
	if _export_path.is_empty():
		return

	print("[GDShield] Post-export hardening triggered for: ", _export_path)
	var root_dir: String = ProjectSettings.globalize_path("res://")
	var python_bin: String = "python"
	var script_path: String = root_dir.path_join("tools/gdshield/gdshield.py")

	if not FileAccess.file_exists(script_path):
		print("[GDShield] WARNING: gdshield.py not found at: ", script_path)
		return

	var export_dir: String = _export_path.get_base_dir()
	var base_name: String = _export_path.get_file().get_basename()
	var pck_path: String = export_dir.path_join(base_name + ".pck")
	var exe_path: String = _export_path if _export_path.ends_with(".exe") else ""

	var output: Array = []

	# 1. Harden PCK & EXE
	if FileAccess.file_exists(pck_path):
		var args: Array = [script_path, "harden", "--pck", pck_path]
		if not exe_path.is_empty() and FileAccess.file_exists(exe_path):
			args.append("--exe")
			args.append(exe_path)
		var code: int = OS.execute(python_bin, args, output, true)
		print("[GDShield] PCK Harden (exit ", code, "): ", "".join(output))

	# 2. Strip native binaries in export directory
	var dir: DirAccess = DirAccess.open(export_dir)
	if dir:
		dir.list_dir_begin()
		var file_name: String = dir.get_next()
		while not file_name.is_empty():
			if not dir.current_is_dir() and (file_name.ends_with(".dll") or file_name.ends_with(".so")):
				var bin_file: String = export_dir.path_join(file_name)
				output.clear()
				var code: int = OS.execute(python_bin, [script_path, "strip-dll", "--path", bin_file], output, true)
				print("[GDShield] Stripped: ", file_name, " (exit ", code, ")")
			file_name = dir.get_next()

	# 3. Minify frontend web assets if present
	for web_folder: String in ["ui", "web", "html"]:
		var web_dir: String = root_dir.path_join(web_folder)
		if DirAccess.dir_exists_absolute(web_dir):
			output.clear()
			var code: int = OS.execute(python_bin, [script_path, "minify-web", "--dir", web_dir], output, true)
			print("[GDShield] Web Minify '", web_folder, "' (exit ", code, ")")
