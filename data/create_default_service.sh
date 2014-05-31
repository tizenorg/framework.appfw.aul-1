mkdir -p $OUTDIR
pushd $OUTDIR

mkdir -p contact/cmds
mkdir -p contact/apps

echo 0 > contact/cmds/create
echo 0 > contact/cmds/view
echo 0 > contact/cmds/edit
echo 1 > contact/cmds/search
echo "" > contact/apps/com.samsung.contacts

mkdir -p calendar/cmds
mkdir -p calendar/apps

echo 0 > calendar/cmds/create
echo 0 > calendar/cmds/view
echo "" > calendar/apps/com.samsung.efl-calendar

mkdir -p memo/cmds
mkdir -p memo/apps

echo 0 > memo/cmds/create
echo 0 > memo/cmds/view
echo "" > memo/apps/com.samsung.memo

mkdir -p email/cmds
mkdir -p email/apps

echo 0 > email/cmds/create
echo 0 > email/cmds/view
echo "" > email/apps/com.samsung.email

mkdir -p message/cmds
mkdir -p message/apps

echo 0 > message/cmds/create
echo 0 > message/cmds/view
echo "" > message/apps/com.samsung.message

mkdir -p camera/cmds
mkdir -p camera/apps

echo 1 > camera/cmds/take_picture
echo 1 > camera/cmds/rec_video
echo 1 > camera/cmds/read_barcode
echo "" > camera/apps/com.samsung.camera-app

mkdir -p voice_record/cmds
mkdir -p voice_record/apps

echo 1 > voice_record/cmds/rec_voice
echo "" > voice_record/apps/com.samsung.voicerecorder

mkdir -p file_browser/cmds
mkdir -p file_browser/apps

echo 0 > file_browser/cmds/browse
echo "" > file_browser/apps/com.samsung.myfile

mkdir -p map/cmds
mkdir -p map/apps

echo 0 > map/cmds/show_place
echo 0 > map/cmds/route_path

mkdir -p alarm/cmds
mkdir -p alarm/apps

echo 0 > alarm/cmds/create
echo "" > alarm/apps/com.samsung.alarm

mkdir -p search/cmds
mkdir -p search/apps

echo 1 > search/cmds/search
echo "" > search/apps/com.samsung.smartsearch

mkdir -p voice_call/cmds
mkdir -p voice_call/apps

echo 0 > voice_call/cmds/mtcall
echo 0 > voice_call/cmds/mocall
echo "" > voice_call/apps/com.samsung.voice-call-ui

mkdir -p video_call/cmds
mkdir -p video_call/apps

echo 0 > video_call/cmds/mtcall
echo 0 > video_call/cmds/mocall
echo "" > video_call/apps/com.samsung.vtmain

popd 

sync

