#!/usr/bin/env python3
"""
Master script for NewWave Group (NWG) External Attack Surface Management (EASM).
This is the main orchestrator that runs all scanning modules in sequence.
"""

import os
import sys
import json
import time
import logging
import signal
import threading
from pathlib import Path
import toml
from domainDetection import owner_test
from domainDetection import goggle_update
from domainDetection import sesearch
from domainDetection import shodsearch
from domainControl import domainControl
from datetime import datetime
from schedule import every, run_pending
from time import sleep

# Add the current directory to the Python path
current_dir = Path(__file__).parent
sys.path.append(str(current_dir))

owner_ini_exec = True
sesearch_ini_exec = True
shod_ini_exec = True
doco_ini_exec = True

owner_current_step = 0
sesearch_current_step = 0
shod_current_step = 0
doco_current_step = 0
with open("config.toml", "r") as file:
    config = toml.load(file)


#region Main functions


def ddMain():
    sesearch_frequency = config["domaindetection"]["general"]["sesearch-frequency"]
    sesearch_step = config["domaindetection"]["general"]["sesearch-step"]
    sesearch_start_minutes = config["domaindetection"]["general"][
        "sesearch-start-minutes"
    ]
    shodsearch_frequency = config["domaindetection"]["general"]["shodsearch-frequency"]
    shodsearch_step = config["domaindetection"]["general"]["shodsearch-step"]
    shodsearch_start_minutes = config["domaindetection"]["general"][
        "shodsearch-start-minutes"
    ]
    owner_test_frequency = config["domaindetection"]["general"]["owner-test-frequency"]
    owner_test_step = config["domaindetection"]["general"]["owner-test-step"]
    owner_test_start_minutes = config["domaindetection"]["general"][
        "owner-test-start-minutes"
    ]
    owner_test_immediate = config["domaindetection"]["general"]["owner-test-immediate"]

    doco_frequency = config["domaincontrol"]["general"]["domaincontrol-frequency"]
    doco_step = config["domaincontrol"]["general"]["domaincontrol-step"]
    doco_start_minutes = config["domaincontrol"]["general"]["domaincontrol-start-minutes"]

    def run_thread(task, targs):
        if not isinstance(targs, tuple):
            targs = (targs,)
        thread = threading.Thread(target=task, args=targs)
        thread.start()

    #  threads = []

    #  Initial execution
    if sesearch_ini_exec or shod_ini_exec or owner_ini_exec or doco_ini_exec:
        if sesearch_ini_exec:
            run_thread(
                ses, (sesearch_step, owner_test_immediate, True, sesearch_start_minutes)
            )
        if shod_ini_exec:
            run_thread(
                shod,
                (shodsearch_step, owner_test_immediate, True, shodsearch_start_minutes),
            )
        if not owner_test_immediate and owner_ini_exec:
            run_thread(owner, (owner_test_step, True, owner_test_start_minutes))
        if doco_ini_exec:
            run_thread(doco, (doco_step, True, doco_start_minutes))

    #  Executions after initial
    if not sesearch_ini_exec:
        every(sesearch_frequency).minutes.do(
            run_thread, ses, (sesearch_step, owner_test_immediate)
        )
    if not shod_ini_exec:
        every(shodsearch_frequency).minutes.do(
            run_thread, shod, (shodsearch_step, owner_test_immediate)
        )
    if not owner_test_immediate:
        every(owner_test_frequency).minutes.do(run_thread, owner, (owner_test_step))
    if not doco_ini_exec:
        every(doco_frequency).minutes.do(run_thread, doco, (doco_step))
    while True:
        run_pending()


#endregion


#region Wrapper functions


def ses(step, imm, ini_exec=False, start_minutes=0):
    with open(config["filepaths"]["companies-list"], "r", encoding="utf-8") as file:
        comp_list = json.load(file)
    index_len = len(comp_list)
    print(index_len)
    if ini_exec:
        sleep(60 * start_minutes)
        global sesearch_ini_exec
    sesearch_ini_exec = False
    global sesearch_current_step
    global lock
    with lock:
        print(f"{datetime.now()} ses {lock}")
        for item in comp_list:
            if (
                item["id"] >= sesearch_current_step
                and item["id"] < step
                and item["id"] != 0
            ):
                sesearch.sesearch(f"{item["name"]}", item["id"])
        if config["domaindetection"]["general"]["goggle-update-on"]:
            goggle_add()
        if imm:
            with open(
                config["filepaths"]["unevaluated-list"], "r", encoding="utf-8"
            ) as file:
                uneval_list = json.load(file)
            for item in uneval_list:
                owner_test.initiate(item["id"])
                print(item["id"])
    sesearch_current_step += step


def shod(step, imm, ini_exec=False, start_minutes=0):
    with open(config["filepaths"]["companies-list"], "r", encoding="utf-8") as file:
        comp_list = json.load(file)
    index_len = len(comp_list)
    print(index_len)
    if ini_exec:
        sleep(60 * start_minutes)
        global shod_ini_exec
    shod_ini_exec = False
    global shod_current_step
    global lock
    with lock:
        print(f"{datetime.now()} shod {lock}")
        for item in comp_list:
            if (
                item["id"] >= shod_current_step
                and item["id"] < step
                and item["id"] != 0
            ):
                shodsearch.org_adder(item["id"])
                shodsearch.domain_finder(item["id"])
        if config["domaindetection"]["general"]["goggle-update-on"]:
            goggle_add()
        if imm:
            with open(
                config["filepaths"]["unevaluated-list"], "r", encoding="utf-8"
            ) as file:
                uneval_list = json.load(file)
                for item in uneval_list:
                    owner_test.initiate(item["id"])
                    print(item["id"])
    shod_current_step += step


def owner(step, ini_exec=False, start_minutes=0):
    with open(config["filepaths"]["unevaluated-list"], "r", encoding="utf-8") as file:
        uneval_list = json.load(file)
    index_len = len(uneval_list)
    print(index_len)
    if ini_exec:
        sleep(60 * start_minutes)
        global owner_ini_exec
    owner_ini_exec = False
    global owner_current_step
    global lock
    with lock:
        print(f"{datetime.now()} owner {lock}")
        for item in uneval_list:
            if (
                item["id"] >= owner_current_step
                and item["id"] < owner_current_step + step
            ):
                owner_test.initiate(item["id"])
    owner_current_step += step


def goggle_add():
    full_goggle_path = f"{config["domaindetection"]["sesearch"]["goggle-dir"]}{config["domaindetection"]["sesearch"]["goggle-name"]}"
    with open(full_goggle_path, "r", encoding="utf-8") as file:
        goggle_content = file.read()
    with open(config["filepaths"]["unevaluated-list"], "r", encoding="utf-8") as file:
        unevaluated_content = json.load(file)
    domain_list = [item["domain"] for item in unevaluated_content]
    for domain in domain_list:
        if domain not in goggle_content:
            goggle_update.update(domain)


def doco(step, ini_exec=False, start_minutes=0):
    with open(config["filepaths"]["companies-list"], "r", encoding="utf-8") as file:
        comp_list = json.load(file)
    index_len = len(comp_list)
    print(index_len)
    if ini_exec:
        sleep(60 * start_minutes)
        global doco_ini_exec
    doco_ini_exec = False
    global doco_current_step
    for item in comp_list:
        if (
            item["id"] >= doco_current_step
            and item["id"] < step
            and item["id"] != 0
        ):
            for domain in item["domains"]:
                print(f"🔍 Starting scan for domain: {domain}")
                domainControl.main(domain)


#endregion


if __name__ == "__main__":
    current_time = datetime.now()
    lock = threading.Lock()
    print(f"Starting time: {current_time}")
    ddMain()
