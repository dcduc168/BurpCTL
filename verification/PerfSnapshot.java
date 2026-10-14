import sun.jvmstat.monitor.MonitoredHost;
import sun.jvmstat.monitor.VmIdentifier;
import sun.jvmstat.monitor.LongMonitor;

/** Reads existing JVM performance counters without enabling a management agent. */
public final class PerfSnapshot {
    public static void main(String[] args) throws Exception {
        var id = new VmIdentifier(args[0]);
        var host = MonitoredHost.getMonitoredHost(id);
        var vm = host.getMonitoredVm(id, 1000);
        try {
            long heap = 0;
            for (var counter : vm.findByPattern("sun\\.gc\\.generation\\.[0-9]+\\.space\\.[0-9]+\\.used"))
                if (counter instanceof LongMonitor value) heap += value.longValue();
            var threads = (LongMonitor)vm.findByName("java.threads.live");
            long gc = 0;
            for (var counter : vm.findByPattern("sun\\.gc\\.collector\\.[0-9]+\\.invocations"))
                if (counter instanceof LongMonitor value) gc += value.longValue();
            System.out.println("{\"heap_used_bytes\":" + heap + ",\"live_threads\":" + threads.longValue() + ",\"gc_count\":" + gc + "}");
        } finally { host.detach(vm); }
    }
}
