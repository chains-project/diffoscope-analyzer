def report_section_init(source1, source2) -> str:
    report = "\n<details closed>"
    report += "<summary>"
    report += f"Source 1: {source1}\n\n"
    report += f"Source 2: {source2}\n\n"
    report += "</summary>"

    return report

def report_section_end() -> str:
    return "</details>\n"
