Name:       aul
Summary:    App utility library
Version:    0.2.3.0
Release:    6
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source101:  ac.service
Source102:  launchpad-preload.service

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
BuildRequires:  pkgconfig(app-checker)
BuildRequires:  pkgconfig(app-checker-server)
BuildRequires:  pkgconfig(rua)
BuildRequires:  pkgconfig(ecore-x)
BuildRequires:  pkgconfig(ecore-input)
BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(libsmack)
#BuildRequires:  pkgconfig(system-resource)
BuildRequires:  pkgconfig(libresourced)
BuildRequires:  pkgconfig(security-server)

%define feature_appfw_integrated_contact_phone 1
%define feature_appfw_multi_instance 1
%define feature_appfw_process_pool 1
%define keepstatic 1
%if "%{?tizen_profile_name}" == "wearable"
%define appfw_feature_process_pool_common 1
%define appfw_feature_hw_rendering 0
%elseif "%{?tizen_profile_name}" == "mobile"
%define appfw_feature_process_pool_common 0
%define appfw_feature_hw_rendering 1
%endif
%define appfw_feature_priority_change 1
%define appfw_feature_default_fake_image 0
%define appfw_feature_data_control 1
%define appfw_feature_debug_launchpad 1
%define appfw_feature_app_control_lite 0
%define appfw_feature_native_launchpad 0
%if "%{?tizen_profile_name}" == "wearable"
%define appfw_feature_bg_process_limit 0
%define appfw_feature_app_checker 0
%define appfw_feature_tts_mode 1
%elseif "%{?tizen_profile_name}" == "mobile"
%define appfw_feature_bg_process_limit 1
%define appfw_feature_app_checker 1
%define appfw_feature_tts_mode 0
%endif
%define appfw_feature_ultra_power_saving_mode 0
%if "%{?tizen_profile_name}" == "wearable"
%define appfw_feature_visibility_check_by_lcd_status 1
%elseif "%{?tizen_profile_name}" == "mobile"
%define appfw_feature_visibility_check_by_lcd_status 0
%endif

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
%if 0%{?feature_appfw_process_pool}
_APPFW_FEATURE_PROCESS_POOL=ON
 %if 0%{?appfw_feature_process_pool_common}
 _APPFW_FEATURE_PROCESS_POOL_COMMON=ON
 %else
  %if 0%{?appfw_feature_hw_rendering}
  _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING=ON
  %endif
 %endif
%endif
%if 0%{?feature_appfw_multi_instance}
_APPFW_FEATURE_MULTI_INSTANCE=ON
%endif
%if 0%{?feature_appfw_integrated_contact_phone}
_APPFW_FEATURE_CONTACT_PHONE_AS_ONE_APP=ON
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
%if 0%{?appfw_feature_native_launchpad}
_APPFW_FEATURE_NATIVE_LAUNCHPAD=ON
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
%if 0%{?appfw_feature_visibility_check_by_lcd_status}
_APPFW_FEATURE_VISIBILITY_CHECK_BY_LCD_STATUS=ON
%endif

cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-D_APPFW_FEATURE_PROCESS_POOL:BOOL=${_APPFW_FEATURE_PROCESS_POOL} \
	-D_APPFW_FEATURE_PROCESS_POOL_COMMON:BOOL=${_APPFW_FEATURE_PROCESS_POOL_COMMON} \
	-D_APPFW_FEATURE_PROCESS_POOL_HW_RENDERING:BOOL=${_APPFW_FEATURE_PROCESS_POOL_HW_RENDERING} \
	-D_APPFW_FEATURE_MULTI_INSTANCE:BOOL=${_APPFW_FEATURE_MULTI_INSTANCE} \
	-D_APPFW_FEATURE_MULTI_WINDOW:BOOL=${_APPFW_FEATURE_MULTI_WINDOW} \
	-D_APPFW_FEATURE_CHANGEABLE_COLOR:BOOL=${_APPFW_FEATURE_CHANGEABLE_COLOR} \
	-D_APPFW_FEATURE_CPU_BOOST:BOOL=${_APPFW_FEATURE_CPU_BOOST} \
	-D_APPFW_FEATURE_CONTACT_PHONE_AS_ONE_APP:BOOL=${_APPFW_FEATURE_CONTACT_PHONE_AS_ONE_APP} \
	-D_APPFW_FEATURE_PRIORITY_CHANGE:BOOL=${_APPFW_FEATURE_PRIORITY_CHANGE} \
	-D_APPFW_FEATURE_DEFAULT_FAKE_IMAGE:BOOL=${_APPFW_FEATURE_DEFAULT_FAKE_IMAGE} \
	-D_APPFW_FEATURE_DATA_CONTROL:BOOL=${_APPFW_FEATURE_DATA_CONTROL} \
	-D_APPFW_FEATURE_DEBUG_LAUNCHPAD:BOOL=${_APPFW_FEATURE_DEBUG_LAUNCHPAD} \
	-D_APPFW_FEATURE_APP_CONTROL_LITE:BOOL=${_APPFW_FEATURE_APP_CONTROL_LITE} \
	-D_APPFW_FEATURE_NATIVE_LAUNCHPAD:BOOL=${_APPFW_FEATURE_NATIVE_LAUNCHPAD} \
	-D_APPFW_FEATURE_WMS_CONNECTION_CHECK:BOOL=${_APPFW_FEATURE_WMS_CONNECTION_CHECK} \
	-D_APPFW_FEATURE_BG_PROCESS_LIMIT:BOOL=${_APPFW_FEATURE_BG_PROCESS_LIMIT} \
	-D_APPFW_FEATURE_APP_CHECKER:BOOL=${_APPFW_FEATURE_APP_CHECKER} \
	-D_APPFW_FEATURE_TTS_MODE:BOOL=${_APPFW_FEATURE_TTS_MODE} \
	-D_APPFW_FEATURE_ULTRA_POWER_SAVING_MODE:BOOL=${_APPFW_FEATURE_ULTRA_POWER_SAVING_MODE} \
	-D_APPFW_FEATURE_VISIBILITY_CHECK_BY_LCD_STATUS:BOOL=${_APPFW_FEATURE_VISIBILITY_CHECK_BY_LCD_STATUS} \
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
install -m0644 %SOURCE102 %{buildroot}%{_libdir}/systemd/system/launchpad-preload.service
ln -s ../launchpad-preload.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/launchpad-preload.service
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}


%post
vconftool set -t int db/setting/effect_image 1 -f -s system::vconf_inhouse


%files
%manifest aul.manifest
%attr(0644,root,root) %{_libdir}/libaul.so.0
%attr(0644,root,root) %{_libdir}/libaul.so.0.1.0
%if 0%{?appfw_feature_default_fake_image}
%attr(0755,root,root) %{_bindir}/config_splash.sh
%endif
%{_bindir}/aul_test
%{_bindir}/launch_app
%{_bindir}/open_app
/usr/share/aul/miregex/*
/usr/share/aul/preload_list.txt
/usr/share/aul/preexec_list.txt
%if 0%{?appfw_feature_default_fake_image}
/usr/share/splash_images/*
%endif
%{_bindir}/launchpad_preloading_preinitializing_daemon
%{_bindir}/amd
%{_bindir}/daemon-manager-release-agent
%{_bindir}/daemon-manager-launch-agent
%{_libdir}/systemd/system/ac.service
%{_libdir}/systemd/system/multi-user.target.wants/ac.service
%{_libdir}/systemd/system/launchpad-preload.service
%{_libdir}/systemd/system/multi-user.target.wants/launchpad-preload.service
/usr/share/license/%{name}

%files devel
%{_includedir}/aul/*.h
%{_includedir}/aul/launch/*.h
%{_includedir}/aul/launchpad/*.h
%{_libdir}/*.so
%{_libdir}/*.a
%{_libdir}/pkgconfig/*.pc
