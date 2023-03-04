extends Control

@onready var first_src_ip_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer/FirstSrcIp
@onready var last_src_ip_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer/LastSrcIp
@onready var first_dest_ip_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer/FirstDstIp
@onready var last_dest_ip_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer/LastDstIp
@onready var protocol_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer/Protocol
@onready var acl_number_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer/AclNumber
@onready var src_details_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer/SrcDetails
@onready var dst_details_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer/DstDetails
@onready var output_acls := $PanelContainer/VBoxContainer/HBoxContainer/VBoxContainer2/TextEdit
@onready var file_dialog := $PanelContainer/VBoxContainer/SaveFileDialog
@onready var popup := $PanelContainer/VBoxContainer/ConfirmationDialog
@onready var acl_type_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer/AclType
@onready var sort_by_mask_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/SortCheckBox
@onready var title_widget := $PanelContainer/VBoxContainer/HBoxContainer/VBoxContainer2/HBoxContainer2/TitleLabel
@onready var acl_size := $PanelContainer/VBoxContainer/HBoxContainer/VBoxContainer2/HBoxContainer2/AclsSize
@onready var src_hosts_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer/SrcHosts
@onready var dst_hosts_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer/DstHosts
@onready var gen_mode_widget := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer/GenModeOptionButton
var current_acls : Array
# Called when the node enters the scene tree for the first time.
func _ready():
	_on_AclNumber_value_changed(acl_number_widget.value)
	update_src_hosts_number()
	update_dst_hosts_number()

func get_value(ip : String) -> int:
	var value := 0
	var i = 0
	var split = ip.rsplit(".", false, 4)
	for s in split:
		value += s.to_int() << (32 - 8 * ( i + 1 ))
		i += 1
	return value

func update_src_hosts_number(_a : String=""):
	var first_src_ip = first_src_ip_widget.text
	var last_src_ip = last_src_ip_widget.text
	if first_src_ip.count(".") == 3 and last_src_ip.count(".") == 3:
		var first_src_ip_value = get_value(first_src_ip)
		var last_src_ip_value = get_value(last_src_ip)
		src_hosts_widget.text = "%d" % (last_src_ip_value - first_src_ip_value + 1)

func update_dst_hosts_number(_a : String=""):
	var first_dst_ip = first_dest_ip_widget.text
	var last_dst_ip = last_dest_ip_widget.text
	if first_dst_ip.count(".") == 3 and last_dst_ip.count(".") == 3:
		var first_dst_ip_value = get_value(first_dst_ip)
		var last_dst_ip_value = get_value(last_dst_ip)
		dst_hosts_widget.text = "%d" % (last_dst_ip_value - first_dst_ip_value + 1)


func compute_acls_with_deny(first_src : int, last_src : int, first_dst : int, last_dst : int):
	var src_hosts = last_src - first_src + 1
	var src_exponent = int(log(src_hosts) / log(2))
	var src_biggest_block = int(pow(2, src_exponent)) - 1
	var src_mask = ~src_biggest_block
	var src_lower_value = first_src & src_mask if first_src != 0 else 0
	
	var dst_hosts = last_dst - first_dst + 1
	var dst_exponent = int(log(dst_hosts) / log(2))
	var dst_biggest_block = int(pow(2, dst_exponent)) - 1
	var dst_mask = ~dst_biggest_block
	var dst_lower_value = first_dst & dst_mask if first_dst != 0 else 0
	# compute permit acls
	var permit_ranges = compute_acls(src_lower_value, last_src, dst_lower_value, last_dst, "permit")
	if src_lower_value == first_src:
		return permit_ranges
	
	var src_oob_hosts = first_src - src_lower_value -1
	var src_upper_value = src_lower_value + src_oob_hosts if first_src != 0 else 0
	
	# compute deny acls
	var deny_ranges = compute_acls(src_lower_value, src_upper_value, dst_lower_value, last_dst, "deny")
	return deny_ranges + permit_ranges


func to_str_ip(address_value : int):
	var buffer := ""
	for i in range(0, 4):
		if i != 0:
			buffer = str(address_value & 0xff) + "." + buffer
		else:
			buffer = str(address_value & 0xff)
		address_value >>= 8
	return buffer

func ip_range(first_value : int, last_value : int):
	var current := first_value
	var temp := 0
	var counter := 0
	var acls := []
	if last_value == 0: return [{
				"ip-value": current,
				"mask-value": 0,
				"ip-str": to_str_ip(current),
				"mask-str": to_str_ip(0)
	}]
	while current <= last_value:
		temp = current
		counter = 0
		while temp > 0:
			if temp % 2 == 0:
				counter += 1
				temp >>= 1
			else:
				temp = 0
# warning-ignore:narrowing_conversion
		temp = pow(2, counter) - 1
		while current + temp > last_value:
			counter -= 1
# warning-ignore:narrowing_conversion
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

func merge_ranges(src_range : Array, dst_range : Array, action : String):
	var merged_ranges = []
	for src in src_range:
		for dst in dst_range:
			merged_ranges.append(
				{
					"action": action,
					"src": src,
					"dst": dst
				}
			)
	return merged_ranges

func compute_acls(first_src : int, last_src : int, first_dst : int, last_dst : int, action : String):
	var src_ranges = ip_range(first_src, last_src)
	var dst_ranges = ip_range(first_dst, last_dst)
	var merged_ranges = merge_ranges(src_ranges, dst_ranges, action)
	return merged_ranges

class AclSorter:
	static func sort(a, b):
		if b["src"]["mask-value"] != a["src"]["mask-value"]:
			return b["src"]["mask-value"] < a["src"]["mask-value"]
		else:
			return b["dst"]["mask-value"] < a["dst"]["mask-value"]

var sorted_acls : Array

func show_acls_lines(merged_range : Array,number : int,protocol : String,src_details : String,dst_details : String):
	var buffer := ""
	sorted_acls = merged_range
	for rng in merged_range:
		buffer += "access-list %d %s " % [number, rng['action']]
		if number >= 100:
			buffer += "%s " % protocol
		if rng["src"]["ip-value"] == 0:
			buffer += "any "
		elif rng["src"]["mask-value"] == 0:
			buffer += "host %s " % rng["src"]["ip-str"]
		else:
			buffer += "%s %s " % [rng["src"]["ip-str"], rng["src"]["mask-str"]]
		if number >= 100 and not src_details.is_empty():
			buffer += "%s " % src_details
		if rng["dst"]["ip-value"] == 0:
			buffer += "any "
		elif rng["dst"]["mask-value"] == 0:
			buffer += "host %s " % rng["dst"]["ip-str"]
		else:
			buffer += "%s %s " % [rng["dst"]["ip-str"], rng["dst"]["mask-str"]]
		if number >= 100 and not dst_details.is_empty():
			buffer += "%s " % dst_details
		buffer += "\n"
	output_acls.text = buffer
	




func _generated_acls_button():
	var first_src_ip = first_src_ip_widget.text
	var last_src_ip = last_src_ip_widget.text
	var first_dst_ip = first_dest_ip_widget.text
	var last_dst_ip = last_dest_ip_widget.text
	var first_src_ip_value = get_value(first_src_ip)
	var last_src_ip_value = get_value(last_src_ip)
	var first_dst_ip_value = get_value(first_dst_ip)
	var last_dst_ip_value = get_value(last_dst_ip)
	var action = acl_type_widget.text
	match gen_mode_widget.selected:
		0:#permit
			current_acls = compute_acls(first_src_ip_value, last_src_ip_value, first_dst_ip_value, last_dst_ip_value, action)
		1:#oob
			current_acls = compute_acls_with_deny(first_src_ip_value, last_src_ip_value, first_dst_ip_value, last_dst_ip_value)
		2:#auto
			var permit_only = compute_acls(first_src_ip_value, last_src_ip_value, first_dst_ip_value, last_dst_ip_value, "permit")
			var oob = compute_acls_with_deny(first_src_ip_value, last_src_ip_value, first_dst_ip_value, last_dst_ip_value)
			if oob.size() < permit_only.size():
				current_acls = oob
			else:
				current_acls = permit_only
	_on_sort_by_mask_toggled(sort_by_mask_widget.button_pressed)
	acl_size.text = "(%d)" % current_acls.size()




func _on_edit_checkbox(button_pressed):
	output_acls.editable = button_pressed


func _on_save_button():
	file_dialog.popup_centered_clamped()


func _on_copy_button():
	DisplayServer.clipboard_set(output_acls.text)


func _on_SaveFileDialog_file_selected(path):
	var file := FileAccess.open(path, FileAccess.WRITE)
# warning-ignore:return_value_discarded
	file.store_string(output_acls.text)
	file.close()
	popup.dialog_text = "Your ACLs have been saved successfuly into '" + path + "'"
	popup.popup_centered()

	


func _on_sort_by_mask_toggled(button_pressed: bool):
	if current_acls:
		var source_details = src_details_widget.text
		var dest_details = dst_details_widget.text
		var protocol = protocol_widget.text
		var number = acl_number_widget.value
		if button_pressed:
			var deny_acls : Array = []
			var permit_acls : Array = []
			for acl in current_acls:
				if acl['action'] == "permit":
					permit_acls.append(acl)
				else:
					deny_acls.append(acl)
			deny_acls.sort_custom(Callable(AclSorter,"sort"))
			permit_acls.sort_custom(Callable(AclSorter,"sort"))
			show_acls_lines(deny_acls + permit_acls, number, protocol, source_details, dest_details)
		else:
			show_acls_lines(current_acls, number, protocol, source_details, dest_details)

func _on_AclNumber_value_changed(value : int):
	var extended := value >= 100
	protocol_widget.disabled = not extended
	src_details_widget.editable = extended
	dst_details_widget.editable = extended
	title_widget.text = "Generated %s ACLs" % ("extended" if extended else "standart")



func _on_GenModeOptionButton_item_selected(index):
	acl_type_widget.text = "permit" if index == 0 else "deny"
	acl_type_widget.disabled = index == 1

@onready var first_src_details := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer2/FirstSrcDetails
@onready var last_src_details := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer2/LastSrcDetails
@onready var first_dst_details := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer2/FirstDstDetails
@onready var last_dst_details := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer2/LastDstDetails
@onready var source_hosts := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer2/SrcHostCovered
@onready var destination_hosts := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer2/DstHostCovered
@onready var acl_selected := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/SelectedAcl

func _on_TextEdit_cursor_changed():
	var ln = output_acls.get_caret_line()
	if current_acls and current_acls.size() > ln:
		acl_selected.text = output_acls.get_line(ln)
		var src = current_acls[ln]['src']
		var dst = current_acls[ln]['dst']
		first_src_details.text = src['ip-str']
		last_src_details.text = to_str_ip(src['ip-value'] + src['mask-value'])
		source_hosts.text = String.num_int64(src['mask-value'] + 1) if src['ip-value'] != 0 else "all"
		first_dst_details.text = dst['ip-str']
		last_dst_details.text = to_str_ip(dst['ip-value'] + dst['mask-value'])
		destination_hosts.text = String.num_int64(dst['mask-value'] + 1) if dst['ip-value'] != 0 else "all"



func test_current_acls(src_ip : String, dst_ip : String):
	var src_value := get_value(src_ip)
	var dst_value := get_value(dst_ip)
	var i := 0
	for acl in sorted_acls:
		var action = acl['action']
		var src_acl = acl['src']
		var dst_acl = acl['dst']
		var src_or_op = src_acl['ip-value'] | src_acl['mask-value']
		if src_value | src_acl['mask-value'] == src_or_op or src_acl['ip-value'] == 0:
			var dst_or_op = dst_acl['ip-value'] | dst_acl['mask-value']
			if dst_value | dst_acl['mask-value'] == dst_or_op or dst_acl['ip-value'] == 0:
				output_acls.set_caret_line(i)
				return {
					"action" : action,
					"acl_number" : i + 1,
					"acl_calculated" : i + 1,
					"acl_triggered" : output_acls.get_line(i)
				}
		i += 1
	return {
		"action" : "deny (implicit)",
		"acl_number" : i + 1,
		"acl_calculated" : i + 1,
		"acl_triggered" : "deny any any"
	}
		
@onready var action_triggered := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer3/ActionTriggered
@onready var acl_number_triggered := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer3/AclNumberTriggered
@onready var acl_triggered := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer3/AclTriggered
@onready var acl_calculated := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/GridContainer3/AclCalculated

@onready var test_src_ip := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/TestAclContainer1/TestSrcIp
@onready var test_dst_ip := $PanelContainer/VBoxContainer/HBoxContainer/ScrollContainer/HBoxContainer/VBoxContainer/TestAclContainer1/TestDstIp

func _on_TestAclButton_pressed():
	var result = test_current_acls(test_src_ip.text, test_dst_ip.text)
	action_triggered.text = result['action']
	acl_number_triggered.text = String.num_int64(result['acl_number'])
	acl_triggered.text = result['acl_triggered']
	acl_calculated.text = String.num_int64(result['acl_calculated'])






func _on_fullscreen_button_pressed():
	if DisplayServer.window_get_mode() == DisplayServer.WINDOW_MODE_FULLSCREEN:
		DisplayServer.window_set_mode(DisplayServer.WINDOW_MODE_WINDOWED)
	else:
		DisplayServer.window_set_mode(DisplayServer.WINDOW_MODE_FULLSCREEN)
