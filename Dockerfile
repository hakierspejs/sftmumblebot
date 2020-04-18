FROM python:2.7
RUN pip install protobuf
ADD . .
ENTRYPOINT ./run
