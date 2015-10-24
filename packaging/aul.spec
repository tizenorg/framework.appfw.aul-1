Name:       aul
Summary:    App utility library
Version:    0.2.3.0
Release:    7
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source101:  ac.service

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
BuildRequires:  xdgmime-devel, pkgconfig(xdgmime)
BuildRequires:  pkgconfig(libprivilege-control)
BuildRequires:  pkgconfig(rua)
BuildRequires:  pkgconfig(ecore-x)
BuildRequires:  pkgconfig(ecore-evas)
BuildRequires:  pkgconfig(ecore-input)
BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:  pkgconfig(libresourced)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(ttrace)
BuildRequires:  pkgconfig(vasum)
BuildRequires:  pkgconfig(appfw-env)
BuildRequires:  pkgconfig(capi-system-info)
BuildRequires: pkgconfig(cert-svc)

%define keepstatic 1

%define appfw_feature_process_pool 1
%define appfw_feature_multi_instance 1
%define appfw_feature_hw_rendering 0
%define appfw_feature_priority_change 1
%define appfw_feature_default_fake_image 0
%define appfw_feature_data_control 1
%define appfw_feature_debug_launchpad 1
%define appfw_feature_app_control_lite 0
%define appfw_feature_terminate_unmanageable_app 0
%if "%{?tizen_profile_name}" == "wearable"
%define appfw_feature_bg_process_limit 0
%define appfw_feature_app_checker 0
%define appfw_feature_tts_mode 0
%define appfw_feature_cpu_boost 1
%define appfw_feature_amd_key 1
%define appfw_feature_mmc_support 1
%define appfw_feature_send_home_launch_signal 1
%define appfw_feature_fake_effect 1
%define appfw_feature_effective_appid 0
%define appfw_feature_private_service 1
%define appfw_feature_background_management 1
%else
%if "%{?tizen_profile_name}" == "mobile"
BuildRequires:  pkgconfig(app-checker)
BuildRequires:  pkgconfig(app-checker-server)

%define appfw_feature_bg_process_limit 0
%define appfw_feature_app_checker 1
%define appfw_feature_tts_mode 0
%define appfw_feature_cpu_boost 1
%define appfw_feature_amd_key 1
%define appfw_feature_mmc_support 1
%define appfw_feature_send_home_launch_signal 1
%define appfw_feature_fake_effect 1
%define appfw_feature_effective_appid 1
%define appfw_feature_private_service 1
%define appfw_feature_background_management 1
%else
%if "%{?tizen_profile_name}" == "tv"
%define appfw_feature_bg_process_limit 0
%define appfw_feature_app_checker 0
%define appfw_feature_tts_mode 0
%define appfw_feature_cpu_boost 0
%define appfw_feature_amd_key 0
%define appfw_feature_mmc_support 0
%define appfw_feature_send_home_launch_signal 0
%define appfw_feature_fake_effect 0
%define appfw_feature_effective_appid 0
%define appfw_feature_private_service 0
%define appfw_feature_background_management 0
%endif
%endif
%endif
%define appfw_feature_ultra_power_saving_mode 0
%define appfw_feature_cooldown_mode_support 0
%if "%{?tizen_profile_name}" == "wearable"
%define appfw_feature_visibility_check_by_lcd_status 1
%else
%if "%{?tizen_profile_name}" == "mobile"
%define appfw_feature_visibility_check_by_lcd_status 0
%else
%if "%{?tizen_profile_name}" == "tv"
%define appfw_feature_visibility_check_by_lcd_status 0
%endif
%endif
%endif
%define appfw_feature_amd_module_log 1
%define appfw_feature_expansion_pkg_install 1

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
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif
%if 0%{?appfw_feature_process_pool}
_APPFW_FEATURE_PROCESS_POOL=ON
%endif
%if 0%{?appfw_feature_multi_instance}
_APPFW_FEATURE_MULTI_INSTANCE=ON
%endif
%if 0%{?appfw_feature_priority_change}
_APPFW_FEATURE_PRIORITY_CHANGE=ON
%endif
%if 0%{?appfw_feature_default_fake_image}
_APPFW_FEATURE_DEFAULT_FAKE_IMAGE=ON
%endif
%if 0%{?appfw_feature_data_control}
_APPFW_FEATURE_DATA_CONTROL=ON
%endif
%if 0%{?appfw_feature_debug_launchpad}
_APPFW_FEATURE_DEBUG_LAUNCHPAD=ON
%endif
%if 0%{?appfw_feature_app_control_lite}
_APPFW_FEATURE_APP_CONTROL_LITE=ON
%endif
%if 0%{?appfw_feature_bg_process_limit}
_APPFW_FEATURE_BG_PROCESS_LIMIT=ON
%endif
%if 0%{?appfw_feature_app_checker}
_APPFW_FEATURE_APP_CHECKER=ON
%endif
%if 0%{?appfw_feature_tts_mode}
_APPFW_FEATURE_TTS_MODE=ON
%endif
%if 0%{?appfw_feature_ultra_power_saving_mode}
_APPFW_FEATURE_ULTRA_POWER_SAVING_MODE=ON
%endif
%if 0%{?appfw_feature_cooldown_mode_support}
_APPFW_FEATURE_COOLDOWN_MODE_SUPPORT=ON
%endif
%if 0%{?appfw_feature_amd_module_log}
_APPFW_FEATURE_AMD_MODULE_LOG=ON
%endif
%if 0%{?appfw_feature_expansion_pkg_install}
_APPFW_FEATURE_EXPANSION_PKG_INSTALL=ON
%endif
%if 0%{?appfw_feature_cpu_boost}
_APPFW_FEATURE_CPU_BOOST=ON
%endif
%if 0%{?appfw_feature_background_management}
_APPFW_FEATURE_BACKGROUND_MANAGEMENT=ON
%endif
%if 0%{?appfw_feature_amd_key}
_APPFW_FEATURE_AMD_KEY=ON
%endif
%if 0%{?appfw_feature_mmc_support}
_APPFW_FEATURE_MMC_SUPPORT=ON
%endif
%if 0%{?appfw_feature_send_home_launch_signal}
_APPFW_FEATURE_SEND_HOME_LAUNCH_SIGNAL=ON
%endif
%if 0%{?appfw_feature_fake_effect}
_APPFW_FEATURE_FAKE_EFFECT=ON
%endif
%if 0%{?appfw_feature_effective_appid}
_APPFW_FEATURE_EFFECTIVE_APPID=ON
%endif
%if 0%{?appfw_feature_private_service}
_APPFW_FEATURE_PRIVATE_SERVICE=ON
%endif
%if 0%{?appfw_feature_terminate_unmanageable_app}
_APPFW_FEATURE_TERMINATE_UNMANAGEABLE_APP=ON
%endif

cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-D_APPFW_FEATURE_PROCESS_POOL:BOOL=${_APPFW_FEATURE_PROCESS_POOL} \
	-D_APPFW_FEATURE_MULTI_INSTANCE:BOOL=${_APPFW_FEATURE_MULTI_INSTANCE} \
	-D_APPFW_FEATURE_CHANGEABLE_COLOR:BOOL=${_APPFW_FEATURE_CHANGEABLE_COLOR} \
	-D_APPFW_FEATURE_CPU_BOOST:BOOL=${_APPFW_FEATURE_CPU_BOOST} \
	-D_APPFW_FEATURE_PRIORITY_CHANGE:BOOL=${_APPFW_FEATURE_PRIORITY_CHANGE} \
	-D_APPFW_FEATURE_DEFAULT_FAKE_IMAGE:BOOL=${_APPFW_FEATURE_DEFAULT_FAKE_IMAGE} \
	-D_APPFW_FEATURE_DATA_CONTROL:BOOL=${_APPFW_FEATURE_DATA_CONTROL} \
	-D_APPFW_FEATURE_DEBUG_LAUNCHPAD:BOOL=${_APPFW_FEATURE_DEBUG_LAUNCHPAD} \
	-D_APPFW_FEATURE_APP_CONTROL_LITE:BOOL=${_APPFW_FEATURE_APP_CONTROL_LITE} \
	-D_APPFW_FEATURE_WMS_CONNECTION_CHECK:BOOL=${_APPFW_FEATURE_WMS_CONNECTION_CHECK} \
	-D_APPFW_FEATURE_BG_PROCESS_LIMIT:BOOL=${_APPFW_FEATURE_BG_PROCESS_LIMIT} \
	-D_APPFW_FEATURE_APP_CHECKER:BOOL=${_APPFW_FEATURE_APP_CHECKER} \
	-D_APPFW_FEATURE_TTS_MODE:BOOL=${_APPFW_FEATURE_TTS_MODE} \
	-D_APPFW_FEATURE_ULTRA_POWER_SAVING_MODE:BOOL=${_APPFW_FEATURE_ULTRA_POWER_SAVING_MODE} \
	-D_APPFW_FEATURE_COOLDOWN_MODE_SUPPORT:BOOL=${_APPFW_FEATURE_COOLDOWN_MODE_SUPPORT} \
	-D_APPFW_FEATURE_VISIBILITY_CHECK_BY_LCD_STATUS:BOOL=${_APPFW_FEATURE_VISIBILITY_CHECK_BY_LCD_STATUS} \
	-D_APPFW_FEATURE_AMD_MODULE_LOG:BOOL=${_APPFW_FEATURE_AMD_MODULE_LOG} \
	-D_APPFW_FEATURE_EXPANSION_PKG_INSTALL:BOOL=${_APPFW_FEATURE_EXPANSION_PKG_INSTALL} \
	-D_APPFW_FEATURE_BACKGROUND_MANAGEMENT:BOOL=${_APPFW_FEATURE_BACKGROUND_MANAGEMENT} \
	-D_APPFW_FEATURE_AMD_KEY:BOOL=${_APPFW_FEATURE_AMD_KEY} \
	-D_APPFW_FEATURE_MMC_SUPPORT:BOOL=${_APPFW_FEATURE_MMC_SUPPORT} \
	-D_APPFW_FEATURE_SEND_HOME_LAUNCH_SIGNAL:BOOL=${_APPFW_FEATURE_SEND_HOME_LAUNCH_SIGNAL} \
	-D_APPFW_FEATURE_FAKE_EFFECT:BOOL=${_APPFW_FEATURE_FAKE_EFFECT} \
	-D_APPFW_FEATURE_EFFECTIVE_APPID:BOOL=${_APPFW_FEATURE_EFFECTIVE_APPID} \
	-D_APPFW_FEATURE_PRIVATE_SERVICE:BOOL=${_APPFW_FEATURE_PRIVATE_SERVICE} \
	-D_APPFW_FEATURE_TERMINATE_UNMANAGEABLE_APP:BOOL=${_APPFW_FEATURE_TERMINATE_UNMANAGEABLE_APP} \
	.

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/opt/dbspace
%if 0%{?appfw_feature_default_fake_image}
mkdir -p %{buildroot}/usr/share/splash_images
cp -raf effect_img/* %{buildroot}/usr/share/splash_images
%endif
mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
install -m0644 %SOURCE101 %{buildroot}%{_libdir}/systemd/system/ac.service
ln -s ../ac.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/ac.service
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

mkdir -p %{buildroot}/usr/share/appsvc
cp -R %{_builddir}/%{name}-%{version}/res/arm/usr/share/appsvc/* %{buildroot}/usr/share/appsvc


%post
/sbin/ldconfig
mkdir -p /opt/dbspace
sqlite3 /opt/dbspace/.appsvc.db < /opt/share/appsvc_db.sql
rm -rf /opt/share/appsvc_db.sql

chown 0:5000 /opt/dbspace/.appsvc.db
chown 0:5000 /opt/dbspace/.appsvc.db-journal
chmod 664 /opt/dbspace/.appsvc.db
chmod 664 /opt/dbspace/.appsvc.db-journal
chsmack -a 'app-svc::db' /opt/dbspace/.appsvc.db
chsmack -a 'app-svc::db' /opt/dbspace/.appsvc.db-journal

%postun -p /sbin/ldconfig


%files
%manifest aul.manifest
/opt/share/appsvc_db.sql
%attr(0644,root,root) %{_libdir}/libaul.so.0
%attr(0644,root,root) %{_libdir}/libaul.so.0.1.0
%if 0%{?appfw_feature_default_fake_image}
%attr(0755,root,root) %{_bindir}/config_splash.sh
%endif
%{_bindir}/aul_test
%{_bindir}/launch_app
%{_bindir}/open_app
%{_bindir}/appgroup_info
/usr/share/appsvc/*
/usr/share/aul/miregex/*
/usr/share/aul/preexec_list.txt
%if 0%{?appfw_feature_default_fake_image}
/usr/share/splash_images/*
%endif
%if 0%{?appfw_feature_amd_module_log}
%attr(0755,root,root) /opt/etc/dump.d/module.d/amd_log_dump.sh
%endif
%{_bindir}/amd
%{_libdir}/systemd/system/ac.service
%{_libdir}/systemd/system/multi-user.target.wants/ac.service
/usr/share/license/%{name}

%{_datadir}/dbus-1/system-services/org.tizen.aul.delegator.service
%{_libdir}/systemd/system/aul-delegator-server.service
%{_bindir}/aul-delegator-server

%files devel
%{_includedir}/aul/*.h
%{_includedir}/aul/launch/*.h
%{_includedir}/aul/launchpad/*.h
%{_libdir}/*.so
%{_libdir}/*.a
%{_libdir}/pkgconfig/*.pc
