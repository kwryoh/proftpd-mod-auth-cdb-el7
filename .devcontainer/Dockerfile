FROM centos:7

ARG USERNAME=mockbuild
ARG USER_UID=1000
ARG USER_GID=${USER_UID}
ARG CCACHE_DIR=/home/${USRNAME}/.ccache

#----------------------
# 開発環境の準備
#----------------------
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

# RPMビルド用ユーザーの作成
RUN groupadd mock -g ${USER_GID} \
    && useradd ${USERNAME} -u ${USER_UID} -m -g mock -G users,wheel

# RPMビルド用ユーザーでパッケージインストールができるように権限追加
RUN echo "${USERNAME} ALL=(ALL:ALL) NOPASSWD:/usr/bin/yum, /usr/bin/rpm, /usr/bin/yum-builddep" \
    | EDITOR="tee -a" visudo -f /etc/sudoers.d/${USERNAME}

#----------------------
# RPMビルドユーザー設定
#----------------------
USER ${USERNAME}

# 常時ビルド時にキャッシュを使用するように変更
RUN echo 'export USE_CCACHE=1' >> ~/.bash_profile \
    && echo 'export CCACHE_DIR="${CCACHE_DIR}"' >> ~/.bash_profile
VOLUME [${CCACHE_DIR}]

# 新しいバージョンのGitを使うように変更
RUN echo "source scl_source enable rh-git227" >> ~/.bash_profile

# rpmbuild用初期設定を追加
RUN rpmdev-setuptree
