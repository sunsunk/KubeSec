package hostagent

import "github.com/rjeczalik/notify"

func GetNotifyEvent() notify.Event {
	return notify.Create | notify.Write | notify.InAttrib
}
