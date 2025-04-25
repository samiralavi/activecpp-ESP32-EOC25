FROM ubuntu:22.04

ARG USERNAME=dev_user
ARG USER_UID=1000
ARG USER_GID=$USER_UID
ARG USER_HOME=/home/$USERNAME

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -s /bin/bash \
    #
    # [Optional] Add sudo support. Omit if you don't need to install software after connecting.
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && chown -R $USER_UID:$USER_GID /home/$USERNAME

# install dependencies
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install curl gnupg \
    build-essential bash-completion nano git ca-certificates curl \
    wget gcc-multilib build-essential git tzdata python2 \
    unzip udev usbutils libusb-dev libncurses5-dev libncursesw5-dev \
    libpcre3 libpcre3-dev iputils-ping python3 python3-dev python3-pip \
    flex bison gperf python3-venv ninja-build ccache libffi-dev libssl-dev \
    dfu-util libusb-1.0-0 clang-tidy-14 locales npm \
    && rm -rf /var/lib/apt/lists/*

# install inliner tool to inline web files into single html file
RUN npm install -g inliner

# Set the locale
RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && \
    locale-gen
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8     

# Links for python, pip, and python debugger
RUN ln -s /usr/bin/python3 /usr/bin/python

# Downloads and installs the latest version of cmake
RUN wget https://github.com/Kitware/CMake/releases/download/v3.31.7/cmake-3.31.7-linux-x86_64.sh \
    && chmod +x cmake-3.31.7-linux-x86_64.sh \
    && ./cmake-3.31.7-linux-x86_64.sh --prefix=/usr/local --skip-license

USER $USERNAME

# Update pip
RUN pip3 install --upgrade pip

# installs the specified version of poetry
RUN curl -sSL https://install.python-poetry.org | python3 - --version 1.8.2
ENV PATH="${USER_HOME}/.local/bin:${PATH}"

# Install ESP-IDF
RUN mkdir -p $USER_HOME/esp \
    && cd $USER_HOME/esp \
    && git clone -b release/v5.4 --depth 1 --recursive https://github.com/espressif/esp-idf.git \
    && cd $USER_HOME/esp/esp-idf \
    && ./install.sh esp32s2,esp32s3

USER root

RUN usermod -a -G dialout,plugdev $USERNAME
