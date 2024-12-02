$(document).ready(function() {
	
	let sidebar = document.querySelector(".sidebar");
	let sidebarBtn = document.querySelector(".sidebarBtn");
	sidebarBtn.onclick = function() {
		sidebar.classList.toggle("active");
		if (sidebar.classList.contains("active")) {
			sidebarBtn.classList.replace("bx-menu", "bx-menu-alt-right");
		} else
			sidebarBtn.classList.replace("bx-menu-alt-right", "bx-menu");
	}
	
	if (jQuery.fn.DataTable) {
		jQuery("#example2,#example3,#example4").DataTable({
			columnDefs: [{ width: 10, targets: 0 }],
	  	});
	}
	
	jQuery('.addprop .form-check-input').click(function(){
		if(jQuery(this).is(":checked")){
			jQuery(this).parent().addClass("checked");
		}
		else if(jQuery(this).is(":not(:checked)")){
			jQuery(this).parent().removeClass("checked");
		}
	});

	
	if (jQuery.fn.SumoSelect) {
 		jQuery('.form-select.sel').SumoSelect();
	}
	
//	if (jQuery.fn.select2) {
// 		jQuery('.form-sele').select2();
//	}
	
	
});

