Name:       aul
Summary:    App utility library
Version:    0.0.321
Release:    1
VCS:        magnolia/framework/appfw/aul-1#aul-1_0.0.258-131-g360ea8ecae0545dedf08f426497538e15a3e5cd3
Group:      System/Libraries
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz
Source101:  ac-wearable.service
Source102:  launchpad-preload-wearable.service
Source103:  process-pool-launchpad-preload-wearable.service
Source104:  ac-mobile.service
Source105:  launchpad-preload-mobile.service
Source106:  process-pool-launchpad-preload-mobile.service

Requires(post): /sbin/ldconfig
Requires(post): /usr/bin/systemctl
Requires(postun): /sbin/ldconfig
Requires(postun): /usr/bin/systemctl
Requires(preun): /usr/bin/systemctl

BuildRequires:  cmake
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(x11)
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(ail)
BuildRequires:  xdgmime-devel, pkgconfig(xdgmime)
BuildRequires:  pkgconfig(libprivilege-control)
BuildRequires:  pkgconfig(rua)
BuildRequires:  pkgconfig(ecore-x)
BuildRequires:  pkgconfig(ecore-input)
BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:	pkgconfig(app2sd)
BuildRequires:  pkgconfig(security-server)
%if %{_repository} == "wearable"
BuildRequires:  pkgconfig(system-resource)
BuildRequires:  pkgconfig(deviced)
%endif
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(elementary)
BuildRequires:  pkgconfig(eina)
BuildRequires:  pkgconfig(privacy-manager-client)

%description
Application utility library

%package devel
Summary:    App utility library (devel)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Application utility library (devel)


%prep
%setup -q

%build
%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_ENGINEER_MODE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_ENGINEER_MODE"
export FFLAGS="$FFLAGS -DTIZEN_ENGINEER_MODE"
%endif
cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} \
%if %{_repository} == "wearable"
        -DDEVICE_PROFILE=wearable
%else if %{_repository} == "mobile"
        -DDEVICE_PROFILE=mobile
%endif

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/opt/dbspace
sqlite3 %{buildroot}/opt/dbspace/.mida.db < %{buildroot}/usr/share/aul/mida_db.sql
rm -rf %{buildroot}/usr/share/aul/mida_db.sql
mkdir -p %{buildroot}/usr/share/splash_images
cp -raf effect_img/* %{buildroot}/usr/share/splash_images

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
%if %{_repository} == "wearable"
install -m0644 %SOURCE101 %{buildroot}%{_libdir}/systemd/system/ac.service
ln -s ../ac.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/ac.service
install -m0644 %SOURCE102 %{buildroot}%{_libdir}/systemd/system/launchpad-preload.service
ln -s ../launchpad-preload.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/launchpad-preload.service
install -m0644 %SOURCE103 %{buildroot}%{_libdir}/systemd/system/process-pool-launchpad-preload.service
ln -s ../process-pool-launchpad-preload.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/process-pool-launchpad-preload.service
%else if %{_repository} == "mobile"
install -m0644 %SOURCE104 %{buildroot}%{_libdir}/systemd/system/ac.service
ln -s ../ac.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/ac.service
install -m0644 %SOURCE105 %{buildroot}%{_libdir}/systemd/system/launchpad-preload.service
ln -s ../launchpad-preload.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/launchpad-preload.service
install -m0644 %SOURCE106 %{buildroot}%{_libdir}/systemd/system/process-pool-launchpad-preload.service
ln -s ../process-pool-launchpad-preload.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/process-pool-launchpad-preload.service
%endif

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}


%post
vconftool set -t int db/setting/effect_image 1 -f -s system::vconf_inhouse


%files
%if %{_repository} == "wearable"
%manifest aul-wearable.manifest
%else
%manifest aul-mobile.manifest
%endif
%attr(0644,root,root) %{_libdir}/libaul.so.0
%attr(0644,root,root) %{_libdir}/libaul.so.0.1.0
%attr(0755,root,root) %{_bindir}/aul_service.sh
%attr(0755,root,root) %{_bindir}/aul_service_test.sh
%attr(0755,root,root) %{_bindir}/config_splash.sh
%config(noreplace) %attr(0644,root,app) /opt/dbspace/.mida.db
%config(noreplace) %attr(0644,root,app) /opt/dbspace/.mida.db-journal
%attr(0755,root,root) %{_bindir}/aul_mime.sh
%{_bindir}/aul_test
%{_bindir}/launch_app
%{_bindir}/open_app
/usr/share/aul/miregex/*
/usr/share/aul/service/*
/usr/share/aul/preload_list.txt
/usr/share/aul/preload_list_for_process_pool.txt
/usr/share/aul/preexec_list.txt
/usr/share/splash_images/*
%{_bindir}/launchpad_preloading_preinitializing_daemon
%{_bindir}/process_pool_launchpad_preloading_preinitializing_daemon
%{_bindir}/amd
%{_bindir}/daemon-manager-release-agent
%{_bindir}/daemon-manager-launch-agent
%{_libdir}/systemd/system/ac.service
%{_libdir}/systemd/system/multi-user.target.wants/ac.service
%{_libdir}/systemd/system/launchpad-preload.service
%{_libdir}/systemd/system/multi-user.target.wants/launchpad-preload.service
%{_libdir}/systemd/system/process-pool-launchpad-preload.service
%{_libdir}/systemd/system/multi-user.target.wants/process-pool-launchpad-preload.service
/usr/share/license/%{name}

%files devel
/usr/include/aul/*.h
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
