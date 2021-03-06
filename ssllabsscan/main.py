"""
App"s main
"""
from __future__ import print_function
import csv
import os
import shutil
import sys
import traceback
import datetime
import errno


from ssllabsscan.report_template import REPORT_HTML
from ssllabsscan.ssllabs_client import SSLLabsClient, SUMMARY_COL_NAMES


TARGET_DIR = "./results"
SUMMARY_CSV = "{}/{}".format(TARGET_DIR, "summary.csv")
SUMMARY_HTML = "{}/{}".format(TARGET_DIR, "summary.html")
VAR_TITLE = "{{VAR_TITLE}}"
VAR_DATA = "{{VAR_DATA}}"
DEFAULT_TITLE = "Qualys SSL Labs Analysis Report [" + datetime.datetime.now(datetime.timezone.utc).strftime('%d.%m.%Y %H:%M (UTC)') + "]"
RESOURCE_DIR="resources/"
DEFAULT_STYLES = "styles.css"
STICKY_TABLE_JS = "stickytableheader.js"


def output_summary_html(input_csv, output_html):
    print("Creating {} ...".format(output_html))

    data = ""
    with open(input_csv, "r") as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row[0].startswith("#"):
                data += "<thead>\n<tr><th>{}</th>".format(row[0][1:])
                row.pop(0)
                data += "<th>{}</th></tr>\n".format('</th><th>'.join(row))
                data += "\n</thead>\n<tbody>\n"
            else:
                # css of row
                if row[1][:1] == '-':
                    # hosts without rating due to missing ssl support/unavailable hosts etc.
                    cssclass = 'Z';
                else:
                    cssclass = row[1][:1]
                data += '<tr class="{}">'.format(cssclass)

                data += '<td><a href="https://{}">{}</a></td>'.format(row[0], row[0])
                row.pop(0)

                # get the link to the full report
                complete_report = row.pop(-1)


                # SSL Rating fields for this row
                data += '<td>{}</td>'.format('</td><td>'.join(row))

                # append the link to the full report
                data += '<td><a href="{}">FULL REPORT</a></td></tr>\n'.format(complete_report)

        data += "\n</tbody>\n"

    # Replace the target string
    content = REPORT_HTML
    content = content.replace(VAR_TITLE, DEFAULT_TITLE)
    content = content.replace(VAR_DATA, data)

    # Write the file out again
    with open(output_html, "w") as file:
        file.write(content)

    # copy styles.css
    shutil.copyfile(os.path.join(os.path.dirname(__file__), RESOURCE_DIR+DEFAULT_STYLES), os.path.join(os.path.dirname(output_html), DEFAULT_STYLES))

    # copy sticky table javascript file
    shutil.copyfile(os.path.join(os.path.dirname(__file__), RESOURCE_DIR+STICKY_TABLE_JS), os.path.join(os.path.dirname(output_html), STICKY_TABLE_JS))


def process(
        server_list_file, check_progress_interval_secs=30,
        summary_csv=SUMMARY_CSV, summary_html=SUMMARY_HTML
):
    ret = 0
    # read from input file
    with open(server_list_file) as f:
        content = f.readlines()
    servers = [x.strip() for x in content]

    if not os.path.exists(os.path.dirname(SUMMARY_CSV)):
        try:
            os.makedirs(os.path.dirname(SUMMARY_CSV))
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise

    with open(SUMMARY_CSV, "w") as outfile:
        # write column names to file
        outfile.write("#{}\n".format(",".join(str(s) for s in SUMMARY_COL_NAMES)))

    for server in servers:
        try:
            print("Start analyzing {} ...".format(server))
            SSLLabsClient(check_progress_interval_secs).analyze(server, summary_csv)
        except Exception as e:
            print(e)
            traceback.print_stack()
            ret = 1

    output_summary_html(summary_csv, summary_html)
    return ret


def main():
    """
    Entry point of the app.
    """
    if len(sys.argv) != 2:
        print("{} [SERVER_LIST_FILE]".format(sys.argv[0]))
        return 1
    return process(server_list_file=sys.argv[1])


if __name__ == "__main__":
    sys.exit(main())
