package awsrequest

import (
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"reflect"
	"strings"
)

func decodeRESTXMLBody(body []byte, service, path, method string, q url.Values, c wireCatalog, l DecodeLimits) (string, map[string]Value, error) {
	op, p, e := restXMLOperationFromCatalog(service, path, method, q, c, l)
	if e != nil {
		return "", nil, e
	}
	if len(body) == 0 || op == "PutObject" {
		return op, p, nil
	}
	x, e := parseXMLParameters(body, l)
	if e != nil {
		return "", nil, e
	}
	for k, v := range x {
		if old, ok := p[k]; ok && !reflect.DeepEqual(old, v) {
			return "", nil, errors.New("REST-XML path/body evidence conflicts")
		}
		p[k] = v
	}
	return op, p, nil
}
func restXMLOperation(service, path, method string, q url.Values, l DecodeLimits) (string, map[string]Value, error) {
	return restXMLOperationFromCatalog(service, path, method, q, defaultWireCatalog(), l)
}

func restXMLOperationFromCatalog(service, path, method string, q url.Values, c wireCatalog, l DecodeLimits) (string, map[string]Value, error) {
	return restOperationFromCatalog(service, path, method, q, ProtocolRESTXML, c, l)
}
func parseXMLParameters(body []byte, l DecodeLimits) (map[string]Value, error) {
	d := xml.NewDecoder(strings.NewReader(string(body)))
	d.Strict = true
	out := map[string]Value{}
	stack := 0
	tokens := 0
	var current string
	for {
		t, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errors.New("malformed REST-XML body")
		}
		tokens++
		if tokens > 8192 || tokens > l.MaxParameters*4 {
			return nil, errors.New("REST-XML token limit exceeded")
		}
		switch x := t.(type) {
		case xml.StartElement:
			stack++
			if stack > l.MaxDepth {
				return nil, errors.New("REST-XML nesting exceeds limit")
			}
			current = x.Name.Local
		case xml.EndElement:
			stack--
		case xml.CharData:
			s := strings.TrimSpace(string(x))
			if s != "" {
				if len(s) > l.MaxTokenBytes {
					return nil, errors.New("REST-XML value exceeds limit")
				}
				out[current] = Value{Kind: ValueString, String: s}
			}
		case xml.ProcInst, xml.Directive:
			return nil, errors.New("REST-XML declaration is unsupported")
		}
	}
	if stack != 0 {
		return nil, errors.New("malformed REST-XML body")
	}
	return out, nil
}
