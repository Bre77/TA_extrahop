import os
import time
import sys
import json
import requests
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.modularinput import *

class Input(Script):
    MASK = "<encrypted>"
    APP = __file__.split(os.sep)[-3]

    def get_scheme(self):

        scheme = Scheme("ExtraHop")
        scheme.description = ("Grab data from the ExtraHop API")
        scheme.use_external_validation = False
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(Argument(
            name="server",
            title="Server",
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=False
        ))
        scheme.add_argument(Argument(
            name="apikey",
            title="API Key",
            description="ExtraHop User API key with relevant read permissions",
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=True
        ))
        scheme.add_argument(Argument(
            name="limit",
            title="Limit",
            data_type=Argument.data_type_number,
            required_on_create=False,
            required_on_edit=False
        ))
        scheme.add_argument(Argument(
            name="verifyssl",
            title="Verify SSL",
            data_type=Argument.data_type_boolean,
            required_on_create=False,
            required_on_edit=False
        ))
        scheme.add_argument(Argument(
            name="collectaudit",
            title="Collect Audit Events",
            data_type=Argument.data_type_boolean,
            required_on_create=False,
            required_on_edit=False
        ))
        scheme.add_argument(Argument(
            name="collectdetections",
            title="Collect Detections",
            data_type=Argument.data_type_boolean,
            required_on_create=False,
            required_on_edit=False
        ))
        return scheme


    def stream_events(self, inputs, ew):
        # Get Variables
        self.service.namespace['app'] = self.APP
        input_name, input_items = inputs.inputs.popitem()
        kind, name = input_name.split("://")
        checkpointfile = os.path.join(self._input_definition.metadata["checkpoint_dir"], name)
        base = 'https://'+input_items["server"]+'/api/v1/'
        limit = int(input_items["limit"])
        verify = input_items["verifyssl"] == "1"

        # Password Encryption
        updates = {}
        
        for item in ["apikey"]:
            stored_password = [x for x in self.service.storage_passwords if x.username == item and x.realm == name]
            if input_items[item] == self.MASK:
                if len(stored_password) != 1:
                    ew.log(EventWriter.ERROR,"Encrypted {} was not found for {}, reconfigure its value.".format(item,input_name))
                    return
                input_items[item] = stored_password[0].content.clear_password
            else:
                if(stored_password):
                    ew.log(EventWriter.DEBUG,"Removing Current password")
                    self.service.storage_passwords.delete(username=item,realm=name)
                ew.log(EventWriter.DEBUG,"Storing password and updating Input")
                self.service.storage_passwords.create(input_items[item],item,name)
                updates[item] = self.MASK
        if(updates):
            self.service.inputs.__getitem__((name,kind)).update(**updates)

        # https://docs.extrahop.com/8.3/rest-api-guide/
        with requests.Session() as session:
            session.headers.update({'Accept': 'application/json', 'Authorization': 'ExtraHop apikey='+input_items["apikey"]})

            # Audit
            if(input_items["collectaudit"] == "1"):

                # Checkpoint
                try:
                    lastid = int(open(checkpointfile+'_audit', "r").read() or 0)
                except:
                    ew.log(EventWriter.WARN,"No audit offset found, starting at zero")
                    lastid = 0

                nextid = lastid
                offset = 0
                while True:
                    response = session.get(base+'auditlog', params={'offset':offset, 'limit':limit}, verify=verify)
                    if(response.ok):
                        events = response.json()
                        count = len(events)
                        if count == 0:
                            ew.log(EventWriter.WARN,"{} had no events".format(EventWriter.INFO,response.url))
                            break
                        if(offset == 0):
                            nextid = events[0]["id"]
                        for event in events:
                            if event["id"] <= lastid:
                                break
                            ew.write_event(Event(
                                time=event["occur_time"]/1000,
                                host=input_items["server"],
                                source="/api/v1/auditlog",
                                sourcetype="extrahop:audit",
                                data=json.dumps(event['body'], separators=(',', ':'))
                            ))
                        else:
                            offset += count
                            ew.log(EventWriter.INFO,"Making another request with offset {}".format(offset))
                            continue
                        ew.log(EventWriter.DEBUG,"Stopping here")
                        break
                    else:
                        ew.log(EventWriter.WARN,"{} returned status {}".format(EventWriter.INFO,response.url,response.status_code))
                        ew.log(EventWriter.WARN,response.text)
                        break    
                
                ew.close()
                open(checkpointfile+"_audit", "w").write(str(nextid))
            
            # Detections
            if(input_items["collectdetections"] == "1"):

                # Checkpoint
                try:
                    lasttime = int(open(checkpointfile+"_detections", "r").read() or 0)
                except:
                    ew.log(EventWriter.WARN,"No detections offset found, starting at zero")
                    lasttime = 0

                offset = 0
                while True:
                    new = 0
                    payload = {'from':lasttime,'offset':offset,'limit':limit,'sort':[{'direction':'desc','field':'start_time'}]}
                    response = session.post(base+'detections/search', data=json.dumps(payload), verify=verify)
                    if(response.ok):
                        events = response.json()
                        count = len(events)
                        if count == 0:
                            # No events means the offset has gone too far
                            ew.log(EventWriter.WARN,"{} had no events".format(response.url))
                            break
                        if offset == 0 and events[0]["start_time"] > lasttime:
                            # Save the first start_time as the offset for next run if its different
                            open(checkpointfile+"_detections", "w").write(str(events[0]["start_time"]))
                        for event in events:
                            if event["start_time"] <= lasttime:
                                ew.log(EventWriter.DEBUG,"Found old detection: created {}, updated {}, but checkpoint is {} ".format(event["start_time"],event["update_time"],lasttime))
                                break
                            new += 1
                            ew.write_event(Event(
                                time=event["start_time"]/1000,
                                host=input_items["server"],
                                source="/api/v1/detections/search",
                                sourcetype="extrahop:detections",
                                data=json.dumps(event, separators=(',', ':'))
                            ))
                        else:
                            offset += count
                            ew.log(EventWriter.DEBUG,"Making another detections request with offset {}".format(offset))
                            continue
                        ew.log(EventWriter.INFO,"Wrote {} events".format(new))
                        break
                    else:
                        ew.log(EventWriter.WARN,"{} returned status {}".format(EventWriter.INFO,response.url,response.status_code))
                        ew.log(EventWriter.WARN,response.text)
                        break
                
                ew.close()
                
if __name__ == '__main__':
    exitcode = Input().run(sys.argv)
    sys.exit(exitcode)