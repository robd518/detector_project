FROM python:3.9

RUN pip install --upgrade pip

RUN adduser yara
USER yara

RUN pip install --user yara-python

RUN mkdir -p /home/yara/scan_files
RUN mkdir /home/yara/yara_rules

WORKDIR /home/yara

COPY ./detector_with_yara.py .

ENV PATH="/home/yara/.local/bin:${PATH}"

CMD ["python", "detector_with_yara.py"]