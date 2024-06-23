package yqutil

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"github.com/sirupsen/logrus"
	logging "gopkg.in/op/go-logging.v1"
)

// EvaluateExpression evaluates the yq expression, and returns the modified yaml.
func EvaluateExpression(expression string, content []byte) ([]byte, error) {
	logrus.Debugf("Evaluating yq expression: %q", expression)
	tmpYAMLFile, err := os.CreateTemp("", "lima-yq-*.yaml")
	if err != nil {
		return nil, err
	}
	tmpYAMLPath := tmpYAMLFile.Name()
	defer os.RemoveAll(tmpYAMLPath)
	_, err = tmpYAMLFile.Write(content)
	if err != nil {
		return nil, err
	}
	if err = tmpYAMLFile.Close(); err != nil {
		return nil, err
	}

	memory := logging.NewMemoryBackend(0)
	backend := logging.AddModuleLevel(memory)
	logging.SetBackend(backend)
	yqlib.InitExpressionParser()

	encoderPrefs := yqlib.ConfiguredYamlPreferences.Copy()
	encoderPrefs.Indent = 2
	encoderPrefs.ColorsEnabled = false
	encoder := yqlib.NewYamlEncoder(encoderPrefs)
	out := new(bytes.Buffer)
	printer := yqlib.NewPrinter(encoder, yqlib.NewSinglePrinterWriter(out))
	decoder := yqlib.NewYamlDecoder(yqlib.ConfiguredYamlPreferences)

	streamEvaluator := yqlib.NewStreamEvaluator()
	files := []string{tmpYAMLPath}
	err = streamEvaluator.EvaluateFiles(expression, files, printer, decoder)
	if err != nil {
		logger := logrus.StandardLogger()
		for node := memory.Head(); node != nil; node = node.Next() {
			entry := logrus.NewEntry(logger).WithTime(node.Record.Time)
			prefix := fmt.Sprintf("[%s] ", node.Record.Module)
			message := prefix + node.Record.Message()
			switch node.Record.Level {
			case logging.CRITICAL:
				entry.Fatal(message)
			case logging.ERROR:
				entry.Error(message)
			case logging.WARNING:
				entry.Warn(message)
			case logging.NOTICE:
				entry.Info(message)
			case logging.INFO:
				entry.Info(message)
			case logging.DEBUG:
				entry.Debug(message)
			}
		}
		return nil, err
	}

	return out.Bytes(), nil
}

func Join(yqExprs []string) string {
	if len(yqExprs) == 0 {
		return ""
	}
	return strings.Join(yqExprs, " | ")
}
