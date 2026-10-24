"""Windows service entry point, sharing the console agent lifecycle."""
import sys

import servicemanager
import win32service
import win32serviceutil


class BehEDRAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "BehEDRAgent"
    _svc_display_name_ = "BehEDR Endpoint Agent"
    _svc_description_ = "Collects endpoint telemetry for the configured BehEDR server."

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        import agent
        agent._stop.set()

    def SvcDoRun(self):
        import agent
        try:
            agent.main()
        except Exception as exc:
            servicemanager.LogErrorMsg(f"BehEDR stopped: {exc}")
            raise


if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(BehEDRAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(BehEDRAgentService)
