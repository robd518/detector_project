#!/usr/bin/env python3

"""
"Detector" class for the DD Homework assignment.  Here's the general flow of how this works:
1. Compile our YARA rules in the "rule_files" directory using yara-python
2. For every file in the "scan_files" directory:
    a. perform a yara.match() against the file
    b. aggregate the match data using a collections.Counter() into a dictionary
    c. if there's matches, build a pretend "alert" with the aggregated data
    d. include metadata related to the matches
    e. pretend to send the alert to <alerting system> by pretty-printing to console
"""

__author__ = "Rob D'Aveta"
__version__ = "0.0.2"
__email__ = "rob.daveta@gmail.com"
__status__ = "dev"

from collections import Counter
import csv
from datetime import datetime
import json
import os
import yara


class YaraScanner():
    def __init__(self, rule_files_directory, scan_files_directory):
        # Compiled rules
        self.rules = ''

        # We're going to keep a list of all the 'string' matches when we
        # do our rules.match() call with callback.  We'll use this to
        # give our alert additional context to make it useful for the analyst
        self.aggregated_results = {}

        # These are the directories we keep our YARA rules and files we want
        # to scan (the ones we mounted as volumes into our container)
        self.rule_files_directory = rule_files_directory
        self.scan_files_directory = scan_files_directory

    def compile_rules(self):
        ''' Compile the rules in the rule_files_directory '''

        try:
            # Let's compile all of our rule files using yara-python.  Please note
            # that I really dislike one-liners and try to avoid them when I'm
            # able.  In this one-liner, we're generating a dict of "namespace":"path"
            # where "namespace" is the name of the file and "path" is the full path
            # to the rule file
            return yara.compile(filepaths={filename: os.path.join(
                self.rule_files_directory, filename) for filename in os.listdir(self.rule_files_directory)})

        except FileNotFoundError:
            # I'm just raising an exception here, but ideally you'd want some kind
            # of alert/notification that this script failed (like your DataDog
            # agent!)  ( ͡° ͜ʖ ͡°)
            raise

    def callback(self, data):
        ''' This callback function will aggregate the results'''

        self.aggregated_results['matched_rule'] = data['rule']
        self.aggregated_results['matched_rule_desc'] = data['meta']['description']
        self.aggregated_results['matched_rule_author'] = data['meta']['author']
        self.aggregated_results['attack_id'] = data['meta']['attack_id']
        self.aggregated_results['strings_matched'] = dict(
            Counter(string[1] for string in data['strings']))

        return yara.CALLBACK_CONTINUE

    def scan(self, scan_file):
        ''' Scan the file we passed into this container with the rules that we also passed into this container'''
        # You *could* invoke your callback here if you wanted to, maybe to
        # add up the number of times a string was matched inside of a custom
        # dictionary / object, to be used in an alert.  All contextual stuff.
        # I'll go ahead and do that here, just for funsies as the kids say.
        self.rules.match(scan_file, callback=self.callback,
                         which_callbacks=yara.CALLBACK_MATCHES)

    def create_and_send_alert(self, scan_file):
        ''' This function creates an alert to be sent to <whatever thing you use> '''
        # Okay, so hear me out.  I *personally* wouldn't write this function inside
        # of a class.  I'd keep it as its own separate module that I could re-use in
        # other scripts/applications.  I'm only including it here as a demonstration.
        # In terms of a <thing> to use for alerting, I don't know what you use.  Maybe
        # you generate a CEF event and send it to ArcSight (hopefully not, but no judgment
        # here if you do).  Maybe you put things onto a Kafka queue for a system to consume.
        # For the purposes of this homework excercise, I'll create a JSON object and
        # pretty-print it, because we love JSON.  We hates the XMLses, precious!  We
        # *hates* it!  Dirty, nasty XMLses.

        alert = {
            'time': str(datetime.now()),
            'filename': scan_file,
            'yara_scan_results': self.aggregated_results
        }

        print('\n[!] Sending alert!')
        print(json.dumps(alert, indent=4))

    def run(self):
        ''' Main running function '''

        self.rules = self.compile_rules()

        try:
            # When we ran this container, we mounted a directory called 'scan_files'
            # We will run this scanner for every file in that directory, and send
            # an alert if it has matches against our YARA rules
            for filename in os.listdir(self.scan_files_directory):

                # Scan the current file with our YARA rules we compiled earlier
                self.scan(os.path.join(self.scan_files_directory, filename))

                # If there's no matches, don't send an alert.  Maybe you'd still want
                # to log that the activity took place just so you know it *did* run?
                if self.aggregated_results:
                    self.create_and_send_alert(filename)

                # Re-initialize the aggregated results dictionary in prep for
                # the next file we scan
                self.aggregated_results = {}

        except FileNotFoundError:
            # I'm just raising an exception here, but ideally you'd want some kind
            # of alert/notification that this script failed (like your DataDog
            # agent!)  ( ͡° ͜ʖ ͡°)
            raise


if __name__ == '__main__':
    # These are the directories we keep our YARA rules and files we want
    # to scan (the ones we mounted as volumes into our container)
    rule_files_directory = os.path.join(os.getcwd(), 'yara_rules')
    scan_files_directory = os.path.join(os.getcwd(), 'scan_files')

    # Initialize our scanner class
    scanner = YaraScanner(rule_files_directory, scan_files_directory)

    # Run the scanner class' run function which will process the files
    scanner.run()
