import os

def load_artifacts(file_path: str) -> set:
    """Loads strings from a file into a set. Empty lines and spaces are ignored."""
    with open(file_path, "r", encoding="utf-8") as file:
        return {line.strip() for line in file if line.strip()}


def compare_with_baseline(baseline_file: str, inputs_dir: str) -> None:
    """Compares the reference file with other files in the directory.
    Displays and saves a loss and garbage report."""
    baseline = load_artifacts(baseline_file)
    report_lines = []

    for file_name in os.listdir(inputs_dir):
        file_path = os.path.join(inputs_dir, file_name)

        if not file_name.endswith(".txt"):
            continue

        team_set = load_artifacts(file_path)

        losses = baseline - team_set
        garbage = team_set - baseline

        report_lines.append(f"\n___Файл: {file_name}___")
        report_lines.append(f"Потери ({len(losses)}):")
        report_lines.extend(sorted(losses) or ["---"])

        report_lines.append(f"\nМусор ({len(garbage)}):")
        report_lines.extend(sorted(garbage) or ["---"])

        print(f"Файл: {file_name}")
        print(f"  Потери: {len(losses)}")
        print(f"  Мусор: {len(garbage)}\n")

    with open("report.txt", "w", encoding="utf-8") as report_file:
        report_file.write("\n".join(report_lines))


if __name__ == "__main__":
    BASELINE = "all_artifacts.txt"          # pattern
    INPUTS_DIR = "inputs"           # folder with the outputs of other commands

    compare_with_baseline(BASELINE, INPUTS_DIR)
