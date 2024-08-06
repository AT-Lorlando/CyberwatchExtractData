def print_progress_bar(
    iteration,
    total,
    prefix="Progress",
    suffix="",
    decimals=1,
    length=50,
    fill="█",
    printEnd="\r",
):
    iteration = iteration + 1
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + "-" * (length - filledLength)
    print(
        f"\r{prefix} |{bar}| {percent}% | {iteration}/{total} | {suffix}", end=printEnd
    )
    if iteration == total:
        print("")
