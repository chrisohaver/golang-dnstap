package dnstap

import (
	dnstap "github.com/dnstap/golang-dnstap"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// A MqttInput reads dnstap data via subscriptions from a MQTT broker.
type MqttInput struct {
	client mqtt.Client
	topics []string
	qos    byte
	wait   chan bool
	reader dnstap.Reader
	log    dnstap.Logger
}

type nullLogger struct{}

func (n nullLogger) Printf(format string, v ...interface{}) {}

// NewMqttInput creates a MqttInput subscribing to topics from the given broker.
func NewMqttInput(opts *mqtt.ClientOptions, topics []string, qos byte) (input *MqttInput, err error) {
	if err != nil {
		return nil, err
	}
	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return nil, token.Error()
	}
	return &MqttInput{
		client: client,
		topics: topics,
		qos:    qos,
		wait:   make(chan bool),
		log:    nullLogger{},
	}, nil
}

// SetLogger configures a logger for FrameStreamInput read error reporting.
func (input *MqttInput) SetLogger(logger dnstap.Logger) {
	input.log = logger
}

// ReadInto subscribes to the topics and registers a handler to copy messages
// received to the output channel.
//
// ReadInto satisfies the dnstap Input interface.
func (input *MqttInput) ReadInto(output chan []byte) {
	input.client.IsConnected()
	for _, topic := range input.topics {
		input.client.Subscribe(topic, input.qos,
			func(_ mqtt.Client, m mqtt.Message) {
				output <- m.Payload()
			},
		)
	}
}

// Wait never returns since ReadInto immediately returns.
//
// Wait satisfies the dnstap Input interface.
func (input *MqttInput) Wait() {
	select {}
}
