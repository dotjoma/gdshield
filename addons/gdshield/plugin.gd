@tool
extends EditorPlugin

var export_plugin: EditorExportPlugin

func _enter_tree() -> void:
	name = "GDShield"
	var ExportScript = preload("res://addons/gdshield/gdshield_export_plugin.gd")
	export_plugin = ExportScript.new()
	add_export_plugin(export_plugin)
	print("[GDShield] Plugin initialized and export hook active.")

func _exit_tree() -> void:
	if export_plugin:
		remove_export_plugin(export_plugin)
		export_plugin = null
