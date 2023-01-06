package dnstap

import (
	dnstap "github.com/dnstap/golang-dnstap"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"google.golang.org/protobuf/proto"
)

// MqttOutput implements a dnstap Output that publishes dnstap data to an MQTT broker.
type MqttOutput struct {
	outputChannel chan []byte
	client        mqtt.Client
	baseTopic     string
	qos           byte
	wait          chan bool
	log           dnstap.Logger
}

const outputChannelSize = 32

// NewMqttOutput creates a MqttOutput for publishing dnstap data to an MQTT broker.
func NewMqttOutput(opts *mqtt.ClientOptions, baseTopic string, qos byte) (o *MqttOutput, err error) {
	o = new(MqttOutput)
	o.baseTopic = baseTopic
	o.qos = qos
	o.outputChannel = make(chan []byte, outputChannelSize)
	o.wait = make(chan bool)
	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return nil, token.Error()
	}
	o.client = client
	return
}

// SetLogger configures a logger for error events in the MqttOutput
func (o *MqttOutput) SetLogger(logger dnstap.Logger) {
	o.log = logger
}

// GetOutputChannel returns the channel on which the MqttOutput accepts dnstap data.
//
// GetOutputChannel satisfies the dnstap Output interface.
func (o *MqttOutput) GetOutputChannel() chan []byte {
	return o.outputChannel
}

// RunOutputLoop receives dnstap data sent on the output channel, unmarshalls it
// and publishes it to the mqtt broker
//
// RunOutputLoop satisfies the dnstap Output interface.
func (o *MqttOutput) RunOutputLoop() {
	dt := &dnstap.Dnstap{}
	for frame := range o.outputChannel {
		if err := proto.Unmarshal(frame, dt); err != nil {
			o.log.Printf("dnstap.MqttOutput: proto.Unmarshal() failed: %s, returning", err)
			break
		}

		// publish message
		o.client.Publish(o.baseTopic+dt.Type.String(), o.qos, false, frame)
	}
	close(o.wait)
}

// Close closes the output channel and returns when all pending data has been
// written.
//
// Close satisfies the dnstap Output interface.
func (o *MqttOutput) Close() {
	close(o.outputChannel)
	<-o.wait
}
