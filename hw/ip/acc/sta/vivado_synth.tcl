set start_f 10

set outdir reports

set help_text {
Usage: vivado -mode batch -source my_script.tcl -tclargs [options]

Options:
  --top_module <name>   Name of the top module to synthesize.
  --outdir <dir>        Output directory for reports (default: reports).
  -h, --help            Show this help and exit.
}

if {$argc == 0 || [lindex $argv 0] in {"-h" "--help"}} {
    puts $help_text
    exit 0
}

set top_module ""

for {set i 0} {$i < $argc} {incr i} {
  set arg [lindex $argv $i]
  switch -- $arg {
    --top_module {
      incr i
      set top_module [lindex $argv $i]
    }
    --outdir {
      incr i
      set outdir [lindex $argv $i]
    }
    default {
      puts "Unknown option: $arg"
    }
  }
}

set file_utilization $outdir/utilization.txt
set file_utilization_hierarchical $outdir/utilization_hierarchical.txt
set file_timing $outdir/timing.txt
set file_timing_summary $outdir/timing_summary.txt
set file_clocks $outdir/clocks.txt

puts "top_module=$top_module"


source lowrisc_ip_acc_0.1.tcl

source rounding.tcl
source timing.tcl

synth_design -mode out_of_context -top $top_module

opt_design
set ACTIVE_STEP opt_design
 
write_checkpoint -force $outdir/synth.dcp

