# RPMパッケージ　サンプルプロジェクト

## Overview

mod_auth_cdbを組み込んだProFTPDのRPMパッケージを作成するプロジェクトです。

Remote Container 開発環境も準備しているため、環境準備に掛かる手間を減らして作業が可能です。

## 環境

CentOS 7 (or Oracle, RHEL 7)

## 準備（Remote Container利用時は不要）

追加レポジトリをインストールする

```sh
yum install -y epel-release centos-release-scl
```

開発ツールをインストールをします

```sh
yum install -y \
    automake autoconf \
    ccache \
    git rh-git227-git \
    gcc gcc-c++ \
    libtool libtool-ltdl \
    make cmake \
    pkgconfig \
    rpmdevtools rpmlint rpm-build yum-utils \
    sudo
```

ProFTPDに必要なパッケージ類をインストールします

```sh
yum-builddep -y proftpd
```

RPMビルド用ユーザーを作成します。

```sh
groupadd -g 1000 mockbuild
useradd -u 1000 -g mockbuild -G wheel -m -s /bin/bash mockbuild
```

Option 1) RPMビルドユーザーでyumが使えるようsudoersに追加

```sh
echo "mockbuild ALL=(ALL:ALL) NOPASSWD:/usr/bin/yum /usr/bin/rpm" \
  | EDITOR="tee -a" visudo -f /etc/sudoers.d/mockbuild
```

Option 2) 繰り返しビルドした際のビルド時間短縮化のために次の設定をする

```sh
echo 'export USE_CCACHE=1' \
  | sudo -u mockbuild tee -a /home/mockbuild/.bash_profile
```

Option 3) 新しいバージョンのGitをデフォルトにする

```sh
echo 'source scl_source enable rh-git227' \
  | sudo -u mockbuild tee -a /home/mockbuild/.bash_profile
```

## ビルド

ビルドはシステムの破壊を防ぐため一般ユーザーで作業します。
今回は mockbuild ユーザーで以降を行います。

gitで当該プロジェクトをcloneします。

```sh
git clone https://github.com/kwryoh/proftpd-mod-auth-cdb-el7.git
cd proftpd-mod-auth-cdb-el7
```

RPMビルドの作業ディレクトリを設定します。
今回、proftpd-mod-auth-cdb-el7 が対象となります。

```sh
echo "%_topdir ${PWD}" >> ~/.rpmmacros
```

最後に、rpmbuildコマンドでrpmファイルを作成します。

```sh
rpmbuild -ba SPECS/proftpd.spec
```

ビルドが正常に終われば、RPMS, SRPMSにファイルが作成されています。

## インストール方法

次のコマンドでカスタムパッケージをインストールできます。

```sh
yum install RPMS/x86_64/proftpd-auth-cdb-1.3.5e-11.el7.rpm
```

## 備考（公式パッケージのsrc.rpmのダウンロード方法について）

ProFTPDのソースRPMを取得します。次のコマンドを実行するとカレントディレクトリに src.rpm がダウンロードされます。

```sh
yumdownloader --source profptd
```

ダウンロードした src.rpm を展開します。（rpmdev-setuptreeによって ~/rpmbuild に展開されます）

```sh
rpm -ivh proftpd-1.3.5e-*.el7.src.rpm
```

展開されたファイル内のSPECファイル、SOURCEファイルを編集しrpmbuildでビルドする。
RPMS, SRPMSにビルドしたrpmファイルが設置されているので、これを配布しインストールすればカスタムビルドのパッケージを利用できます。
