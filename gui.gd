extends Control

onready var first_ip_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/FirstIp
onready var last_ip_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/LastIp
onready var dest_ip_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/DstIp
onready var mask_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/Mask
onready var protocol_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/Protocol
onready var acl_number_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/AclNumber
onready var src_details_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/SrcDetails
onready var dst_details_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/DstDetails
onready var output_acls := $PanelContainer/HBoxContainer/VBoxContainer2/TextEdit
onready var file_dialog := $PanelContainer/SaveFileDialog
onready var popup := $PanelContainer/ConfirmationDialog
onready var acl_type_widget := $PanelContainer/HBoxContainer/VBoxContainer/GridContainer/AclType

# Called when the node enters the scene tree for the first time.
func _ready():
	pass # Replace with function body.
func get_value(var ip : String):
	var value = 0
	var i = 0
	var split = ip.rsplit(".", false, 4)
	for s in split:
		value += s.to_int() << (32 - 8 * ( i + 1 ))
		i += 1
	return value

func show_acls(var number : int, var first_value : int, var last_value : int, var dstIp : String, var dstMaskIp : String, var f : String, var t : String, var protocol : String):
	var current := first_value
	var temp := 0
	var counter := 0
	var output := ""
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
		output += "access-list " + str(number) + " " + acl_type_widget.text + " " + (protocol if protocol != null else "") + " " + str(current >> 24) + "." + str((current >> 16) & 0xff) + "." + str((current >> 8) & 0xff) + "." + str(current & 0xff) + " " + str((temp >> 24) & 0xff) + "." + str((temp >> 16) & 0xff) + "." + str((temp >> 8) & 0xff) + "." + str(temp & 0xff) + " " + (f if not f.empty() else "") + " " + (dstIp if not dstIp.empty() else "any") + " " + (dstMaskIp if not dstMaskIp.empty() else ("0.0.0.0" if not dstIp.empty() else "")) + " " + (t if not t.empty() else "") + "\n"
		current += temp + 1
	return output

func to_str_ip(var address_value : int):
	var buffer := ""
	for i in range(1, 4):
		if i != 1:
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
				"ip": current,
				"mask": temp
			}
		)
		current += temp + 1
	return acls

func _generated_acls_button():
	var first_ip = first_ip_widget.text
	var last_ip = last_ip_widget.text
	var dst_ip = dest_ip_widget.text
	var mask = mask_widget.text
	var source_details = src_details_widget.text
	var dest_details = dst_details_widget.text
	var protocol = protocol_widget.text
	var first_value = get_value(first_ip)
	var last_value = get_value(last_ip)
	var number = acl_number_widget.value
	var out = show_acls(number, first_value, last_value, dst_ip, mask, source_details, dest_details, protocol)
	output_acls.text = out




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

	
