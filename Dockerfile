FROM python:3

COPY ./AppBackEnd AppBackEnd

WORKDIR /AppBackEnd

RUN pip install -r requirements.txt

RUN python manage.py migrate

CMD ["python","manage.py","runserver", "0.0.0.0:3505"]
