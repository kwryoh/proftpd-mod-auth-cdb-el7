FROM centos:7

ARG USERNAME=mockbuild
ARG USER_UID=1000
ARG USER_GID=${USER_UID}

RUN yum install -y epel-release centos-release-scl
RUN yum install -y \
        automake autoconf \
        ccache \
        git rh-git227-git \
        gcc gcc-c++ \
        libtool libtool-ltdl \
        make cmake \
        pkgconfig \
        rpmdevtools rpmlint rpm-build yum-utils \
        sudo \
    && yum clean all

RUN groupadd mock -g ${USER_GID} \
    && useradd ${USERNAME} -u ${USER_UID} -m -g mock -G users,wheel
RUN echo "${USERNAME}  ALL=(ALL:ALL) NOPASSWD:ALL" | EDITOR="tee -a" visudo -f /etc/sudoers.d/${USERNAME}
RUN echo "source scl_source enable rh-git227" > /etc/profile.d/rh-git227.sh
RUN sudo -u ${USERNAME} rpmdev-setuptree
