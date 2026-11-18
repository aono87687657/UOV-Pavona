sh date

set TOP_MODULE acc
set GENUS_SCRIPT genus.tcl


set nproc [exec nproc]
set_multi_cpu_usage -local_cpu 8
set READ_SOURCES lowrisc_ip_acc_0.1-read-sources

set SCRIPT_DIR "./"

set REPORT_DIR "./"


set TOP_MODULE $env(TOP_MODULE)
set start_f $env(START_F)
set REPORT_DIR $env(OUTDIR)
set PQC_MODE $env(PQC_MODE)


set TOP_PARAMETERS {}

if {$TOP_MODULE in {
    acc
    acc_core
    acc_alu_bignum
    acc_mac_bignum
}} {
    lappend TOP_PARAMETERS [list AccPQCEn $PQC_MODE]
}

############################################
#
# TCL script for Synthesis with Genus
#
############################################
# Required if SRAM blocks are synthesized
set_db hdl_max_memory_address_range 65536

############################################
# Read Sources
############################################
source ${READ_SOURCES}.tcl

############################################
# Library Setup
############################################
set LIB_PATH  "/path/to/asap7/asap7sc7p5t_28/LIB/NLDM/"
set LEF_PATH  "/path/to/asap7/asap7sc7p5t_28/LEF/scaled/"
set TLEF_PATH "/path/to/asap7/asap7sc7p5t_28/techlef_misc"

set LIB_LIST {
	asap7sc7p5t_AO_LVT_TT_nldm_211120.lib \
	asap7sc7p5t_INVBUF_LVT_TT_nldm_220122.lib \
	asap7sc7p5t_OA_LVT_TT_nldm_211120.lib \
	asap7sc7p5t_SEQ_LVT_TT_nldm_220123.lib \
	asap7sc7p5t_SIMPLE_LVT_TT_nldm_211120.lib \
	asap7sc7p5t_AO_SLVT_TT_nldm_211120.lib \
	asap7sc7p5t_INVBUF_SLVT_TT_nldm_220122.lib \
	asap7sc7p5t_OA_SLVT_TT_nldm_211120.lib \
	asap7sc7p5t_SEQ_SLVT_TT_nldm_220123.lib \
	asap7sc7p5t_SIMPLE_SLVT_TT_nldm_211120.lib
}

set LEF_LIST {
	asap7_tech_4x_201209.lef \
	asap7sc7p5t_28_L_4x_220121a.lef \
	asap7sc7p5t_28_SL_4x_220121a.lef
}

set_db init_lib_search_path "$LIB_PATH $LEF_PATH $TLEF_PATH"

set_db / .library "$LIB_LIST"
set_db lef_library "$LEF_LIST"

############################################
# Elaborate Design
############################################

# Effort: none, low, medium, high, express
set_db syn_global_effort low


if {[llength $TOP_PARAMETERS] > 0} {
    puts "Elaborating $TOP_MODULE with parameters: $TOP_PARAMETERS"
    elaborate $TOP_MODULE -parameters $TOP_PARAMETERS
} else {
    puts "Elaborating $TOP_MODULE with default parameters"
    elaborate $TOP_MODULE
}


check_design -unresolved
check_design -combo_loops
check_design -multiple_driver

write_db ${REPORT_DIR}/test.db

quit

