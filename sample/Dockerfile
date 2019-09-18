FROM ubuntu:xenial

# Ensure non-interactive mode
ENV DEBIAN_FRONTEND noninteractive

# Add our user and group first to make sure their IDs get assigned consistently, regardless of whatever dependencies get added
RUN groupadd -r uwsgi && useradd -r -g uwsgi uwsgi

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
ENV CODE_DIR /var/code

## START: GOSU
ENV GOSU_VERSION 1.10
RUN set -x \
    && apt-get update && apt-get install -y --no-install-recommends ca-certificates wget && rm -rf /var/lib/apt/lists/* \
    && dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')" \
    && wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch" \
    && wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch.asc" \
    && export GNUPGHOME="$(mktemp -d)" \
    && gpg --keyserver ha.pool.sks-keyservers.net --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 \
    && gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu \
    && rm -r "$GNUPGHOME" /usr/local/bin/gosu.asc \
    && chmod +x /usr/local/bin/gosu \
    && gosu nobody true \
    && apt-get purge -y --auto-remove ca-certificates wget

## END: GOSU

RUN apt-get update \
    && apt-get install -y --no-install-recommends mysql-client wget software-properties-common libxml2-dev \
    libxmlsec1-dev libmagic1 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN mkdir ${CODE_DIR} && mkdir ${CODE_DIR}/instance && chown -R uwsgi:uwsgi ${CODE_DIR}
WORKDIR ${CODE_DIR}

RUN add-apt-repository ppa:jonathonf/python-3.6 && apt-get update \
    && apt-get install -y --no-install-recommends python3.6-dev libmysqlclient-dev gcc \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.5 1 \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.6 2 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

ENV PYTHON_PIP_VERSION 9.0.1
RUN wget -O /tmp/get-pip.py 'https://bootstrap.pypa.io/get-pip.py' \
    && python3 /tmp/get-pip.py "pip==$PYTHON_PIP_VERSION" \
    && rm /tmp/get-pip.py \
    && pip3 install --no-cache-dir --upgrade --force-reinstall "pip==$PYTHON_PIP_VERSION"

RUN pip3 install --no-cache-dir uwsgi==2.0.14

ADD requirements.txt ${CODE_DIR}/requirements.txt
RUN pip3 install -r requirements.txt

# Python 3-ify exports
ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8

ADD . ${CODE_DIR}
RUN chown -R uwsgi:uwsgi ${CODE_DIR}

COPY docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uwsgi"]
