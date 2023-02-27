extends Control

onready var first_src_ip_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/FirstSrcIp
onready var last_src_ip_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/LastSrcIp
onready var first_dest_ip_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/FirstDstIp
onready var last_dest_ip_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/LastDstIp
onready var protocol_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/Protocol
onready var acl_number_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/AclNumber
onready var src_details_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/SrcDetails
onready var dst_details_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/DstDetails
onready var output_acls := $PanelContainer/HBoxContainer/VBoxContainer2/TextEdit
onready var file_dialog := $PanelContainer/SaveFileDialog
onready var popup := $PanelContainer/ConfirmationDialog
onready var acl_type_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/AclType
onready var sort_by_mask_widget := $PanelContainer/HBoxContainer/VBoxContainer2/HBoxContainer/SortCheckBox
onready var title_widget := $PanelContainer/HBoxContainer/VBoxContainer2/TitleLabel
var current_acls

# Called when the node enters the scene tree for the first time.
func _ready():
	_on_AclNumber_value_changed(acl_number_widget.value)

func get_value(var ip : String):
	var value = 0
	var i = 0
	var split = ip.rsplit(".", false, 4)
	for s in split:
		value += s.to_int() << (32 - 8 * ( i + 1 ))
		i += 1
	return value


func to_str_ip(var address_value : int):
	var buffer := ""
	for i in range(0, 4):
		if i != 0:
			buffer = str(address_value & 0xff) + "." + buffer
		else:
			buffer = str(address_value & 0xff)
		address_value >>= 8
	return buffer

func ip_range(var first_value : int, var last_value : int):
	var current := first_value
	var temp := 0
	var counter := 0
	var acls := []
	while current <= last_value:
		temp = current
		counter = 0
		while temp > 0:
			if temp % 2 == 0:
				counter += 1
				temp >>= 1
			else:
				temp = 0
		temp = pow(2, counter) - 1
		while current + temp > last_value:
			counter -= 1
			temp = pow(2, counter) - 1
		acls.append(
			{
				"ip-value": current,
				"mask-value": temp,
				"ip-str": to_str_ip(current),
				"mask-str": to_str_ip(temp)
			}
		)
		current += temp + 1
	return acls

func merge_ranges(var src_range : Array, var dst_range : Array):
	var merged_ranges = []
	for src in src_range:
		for dst in dst_range:
			merged_ranges.append(
				{
					"src": src,
					"dst": dst
				}
			)
	return merged_ranges

func compute_acls(var first_src : int, var last_src : int, var first_dst : int, var last_dst : int):
	var src_ranges = ip_range(first_src, last_src)
	var dst_ranges = ip_range(first_dst, last_dst)
	var merged_ranges = merge_ranges(src_ranges, dst_ranges)
	return merged_ranges

class AclSorter:
	static func sort(a, b):
		print(b["src"]["mask-value"] , " ", a["src"]["mask-value"])
		return b["src"]["mask-value"] < a["src"]["mask-value"]

func show_acls_lines(var merged_range : Array,
					 var number : int,
					 var protocol : String,
					 var src_details : String,
					 var dst_details : String,
					 var action : String):
	var buffer := ""
	for rng in merged_range:
		buffer += "access-list %d %s " % [number, action]
		if number >= 100:
			buffer += "%s " % protocol
		if rng["src"]["ip-value"] == 0:
			buffer += "any "
		elif rng["src"]["mask-value"] == 0:
			buffer += "host %s " % rng["src"]["ip-str"]
		else:
			buffer += "%s %s " % [rng["src"]["ip-str"], rng["src"]["mask-str"]]
		if number >= 100 and src_details:
			buffer += "%s " % src_details
		if rng["dst"]["ip-value"] == 0:
			buffer += "any "
		elif rng["dst"]["mask-value"] == 0:
			buffer += "host %s " % rng["dst"]["ip-str"]
		else:
			buffer += "%s %s " % [rng["dst"]["ip-str"], rng["dst"]["mask-str"]]
		if number >= 100 and dst_details:
			buffer += "%s " % dst_details
		buffer += "\n"
	output_acls.text = buffer
	

func _generated_acls_button():
	var first_src_ip = first_src_ip_widget.text
	var last_src_ip = last_src_ip_widget.text
	var first_dst_ip = first_dest_ip_widget.text
	var last_dst_ip = last_dest_ip_widget.text
	var source_details = src_details_widget.text
	var dest_details = dst_details_widget.text
	var protocol = protocol_widget.text
	var first_src_ip_value = get_value(first_src_ip)
	var last_src_ip_value = get_value(last_src_ip)
	var first_dst_ip_value = get_value(first_dst_ip)
	var last_dst_ip_value = get_value(last_dst_ip)
	var number = acl_number_widget.value
	var action = acl_type_widget.text
	current_acls = compute_acls(first_src_ip_value, last_src_ip_value, first_dst_ip_value, last_dst_ip_value)
	if sort_by_mask_widget.pressed:
		current_acls.sort_custom(AclSorter, "sort")
	show_acls_lines(current_acls, number, protocol, source_details, dest_details, action)




func _on_edit_checkbox(button_pressed):
	output_acls.readonly = not button_pressed


func _on_save_button():
	file_dialog.popup_centered_clamped()


func _on_copy_button():
	OS.clipboard = output_acls.text


func _on_SaveFileDialog_file_selected(path):
	var file := File.new()
	file.open(path, File.WRITE)
	file.store_string(output_acls.text)
	file.close()
	popup.dialog_text = "Your ACLs have been saved successfuly into '" + path + "'"
	popup.popup_centered()

	


func _on_sort_by_mask_toggled(button_pressed):
	if current_acls:
		current_acls.sort_custom(AclSorter, "sort")
		var source_details = src_details_widget.text
		var dest_details = dst_details_widget.text
		var protocol = protocol_widget.text
		var number = acl_number_widget.value
		var action = acl_type_widget.text
		show_acls_lines(current_acls, number, protocol, source_details, dest_details, action)


func _on_AclNumber_value_changed(value : int):
	var extended := value >= 100
	protocol_widget.disabled = not extended
	src_details_widget.editable = extended
	dst_details_widget.editable = extended
	title_widget.text = "Generated %s ACLs" % ("extended" if extended else "standart")
