rule workbench_simulator_marker_v1
{
    meta:
        description = "Benign Workbench simulator marker (rehearsal)"
    strings:
        $marker = "WORKBENCH-SIMULATOR-MARKER-v1" ascii wide
    condition:
        uint16(0) == 0x5A4D and $marker
}
