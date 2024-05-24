# Open Traffic Generator L1S(Layer1Switch) Model API 0.0.1
# License: MIT

import importlib
import logging
import json
import platform
import yaml
import requests
import urllib3
import io
import sys
import time
import grpc
import semantic_version
import types
import platform
from google.protobuf import json_format

try:
    from openl1s import l1s_pb_pb2_grpc as pb2_grpc
except ImportError:
    import l1s_pb_pb2_grpc as pb2_grpc
try:
    from openl1s import l1s_pb_pb2 as pb2
except ImportError:
    import l1s_pb_pb2 as pb2

try:
    from typing import Union, Dict, List, Any, Literal
except ImportError:
    from typing_extensions import Literal


if sys.version_info[0] == 3:
    unicode = str


openapi_warnings = []


class Transport:
    HTTP = "http"
    GRPC = "grpc"


def api(
    location=None,
    transport=None,
    verify=True,
    logger=None,
    loglevel=logging.INFO,
    ext=None,
    version_check=False,
):
    """Create an instance of an Api class

    generator.Generator outputs a base Api class with the following:
    - an abstract method for each OpenAPI path item object
    - a concrete properties for each unique OpenAPI path item parameter.

    generator.Generator also outputs an HttpApi class that inherits the base
    Api class, implements the abstract methods and uses the common HttpTransport
    class send_recv method to communicate with a REST based server.

    Args
    ----
    - location (str): The location of an Open Traffic Generator server.
    - transport (enum["http", "grpc"]): Transport Type
    - verify (bool): Verify the server's TLS certificate, or a string, in which
      case it must be a path to a CA bundle to use. Defaults to `True`.
      When set to `False`, requests will accept any TLS certificate presented by
      the server, and will ignore hostname mismatches and/or expired
      certificates, which will make your application vulnerable to
      man-in-the-middle (MitM) attacks. Setting verify to `False`
      may be useful during local development or testing.
    - logger (logging.Logger): A user defined logging.logger, if none is provided
      then a default logger with a stdout handler will be provided
    - loglevel (logging.loglevel): The logging package log level.
      The default loglevel is logging.INFO
    - ext (str): Name of an extension package
    """
    params = locals()
    transport_types = ["http", "grpc"]
    if ext is None:
        transport = "http" if transport is None else transport
        if transport not in transport_types:
            raise Exception(
                "{transport} is not within valid transport types {transport_types}".format(
                    transport=transport, transport_types=transport_types
                )
            )
        if transport == "http":
            return HttpApi(**params)
        else:
            return GrpcApi(**params)
    try:
        if transport is not None:
            raise Exception(
                "ext and transport are not mutually exclusive. Please configure one of them."
            )
        lib = importlib.import_module("openl1s_{}.openl1s_api".format(ext))
        return lib.Api(**params)
    except ImportError as err:
        msg = "Extension %s is not installed or invalid: %s"
        raise Exception(msg % (ext, err))


class HttpTransport(object):
    def __init__(self, **kwargs):
        """Use args from api() method to instantiate an HTTP transport"""
        self.location = (
            kwargs["location"]
            if "location" in kwargs and kwargs["location"] is not None
            else "https://localhost:443"
        )
        self.verify = kwargs["verify"] if "verify" in kwargs else False
        self.logger = kwargs["logger"] if "logger" in kwargs else None
        self.loglevel = kwargs["loglevel"] if "loglevel" in kwargs else logging.DEBUG
        if self.logger is None:
            stdout_handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                fmt="%(asctime)s [%(name)s] [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            formatter.converter = time.gmtime
            stdout_handler.setFormatter(formatter)
            self.logger = logging.Logger(self.__module__, level=self.loglevel)
            self.logger.addHandler(stdout_handler)
        self.logger.debug(
            "HttpTransport args: {}".format(
                ", ".join(["{}={!r}".format(k, v) for k, v in kwargs.items()])
            )
        )
        self.set_verify(self.verify)
        self._session = requests.Session()

    def set_verify(self, verify):
        self.verify = verify
        if self.verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.logger.warning("Certificate verification is disabled")

    def _parse_response_error(self, response_code, response_text):
        error_response = ""
        try:
            error_response = yaml.safe_load(response_text)
        except Exception as _:
            error_response = response_text

        err_obj = Error()
        try:
            err_obj.deserialize(error_response)
        except Exception as _:
            err_obj.code = response_code
            err_obj.errors = [str(error_response)]

        raise Exception(err_obj)

    def send_recv(
        self,
        method,
        relative_url,
        payload=None,
        return_object=None,
        headers=None,
        request_class=None,
    ):
        url = "%s%s" % (self.location, relative_url)
        data = None
        headers = headers or {"Content-Type": "application/json"}
        if payload is not None:
            if isinstance(payload, bytes):
                data = payload
                headers["Content-Type"] = "application/octet-stream"
            elif isinstance(payload, (str, unicode)):
                if request_class is not None:
                    request_class().deserialize(payload)
                data = payload
            elif isinstance(payload, OpenApiBase):
                data = payload.serialize()
            else:
                raise Exception("Type of payload provided is unknown")
        response = self._session.request(
            method=method,
            url=url,
            data=data,
            verify=False,
            allow_redirects=True,
            # TODO: add a timeout here
            headers=headers,
        )
        if response.ok:
            if "application/json" in response.headers["content-type"]:
                # TODO: we might want to check for utf-8 charset and decode
                # accordingly, but current impl works for now
                response_dict = yaml.safe_load(response.text)
                if return_object is None:
                    # if response type is not provided, return dictionary
                    # instead of python object
                    return response_dict
                else:
                    return return_object.deserialize(response_dict)
            elif "application/octet-stream" in response.headers["content-type"]:
                return io.BytesIO(response.content)
            else:
                # TODO: for now, return bare response object for unknown
                # content types
                return response
        else:
            self._parse_response_error(response.status_code, response.text)


class OpenApiStatus:
    messages = {}
    # logger = logging.getLogger(__module__)

    @classmethod
    def warn(cls, key, object):
        if cls.messages.get(key) is not None:
            if cls.messages[key] in object.__warnings__:
                return
            # cls.logger.warning(cls.messages[key])
            logging.warning(cls.messages[key])
            object.__warnings__.append(cls.messages[key])
            # openapi_warnings.append(cls.messages[key])

    @staticmethod
    def deprecated(func_or_data):
        def inner(self, *args, **kwargs):
            OpenApiStatus.warn(
                "{}.{}".format(type(self).__name__, func_or_data.__name__),
                self,
            )
            return func_or_data(self, *args, **kwargs)

        if isinstance(func_or_data, types.FunctionType):
            return inner
        OpenApiStatus.warn(func_or_data)

    @staticmethod
    def under_review(func_or_data):
        def inner(self, *args, **kwargs):
            OpenApiStatus.warn(
                "{}.{}".format(type(self).__name__, func_or_data.__name__),
                self,
            )
            return func_or_data(self, *args, **kwargs)

        if isinstance(func_or_data, types.FunctionType):
            return inner
        OpenApiStatus.warn(func_or_data)


class OpenApiBase(object):
    """Base class for all generated classes"""

    JSON = "json"
    YAML = "yaml"
    DICT = "dict"

    __slots__ = ()

    __constraints__ = {"global": []}
    __validate_latter__ = {"unique": [], "constraint": []}

    def __init__(self):
        pass

    def serialize(self, encoding=JSON):
        """Serialize the current object according to a specified encoding.

        Args
        ----
        - encoding (str[json, yaml, dict]): The object will be recursively
            serialized according to the specified encoding.
            The supported encodings are json, yaml and python dict.

        Returns
        -------
        - obj(Union[str, dict]): A str or dict object depending on the specified
            encoding. The json and yaml encodings will return a str object and
            the dict encoding will return a python dict object.
        """
        # TODO: restore behavior
        # self._clear_globals()
        if encoding == OpenApiBase.JSON:
            data = json.dumps(self._encode(), indent=2, sort_keys=True)
        elif encoding == OpenApiBase.YAML:
            data = yaml.safe_dump(self._encode())
        elif encoding == OpenApiBase.DICT:
            data = self._encode()
        else:
            raise NotImplementedError("Encoding %s not supported" % encoding)
        # TODO: restore behavior
        # self._validate_coded()
        return data

    def _encode(self):
        raise NotImplementedError()

    def deserialize(self, serialized_object):
        """Deserialize a python object into the current object.

        If the input `serialized_object` does not match the current
        openapi object an exception will be raised.

        Args
        ----
        - serialized_object (Union[str, dict]): The object to deserialize.
            If the serialized_object is of type str then the internal encoding
            of the serialized_object must be json or yaml.

        Returns
        -------
        - obj(OpenApiObject): This object with all the
            serialized_object deserialized within.
        """
        # TODO: restore behavior
        # self._clear_globals()
        if isinstance(serialized_object, (str, unicode)):
            serialized_object = yaml.safe_load(serialized_object)
        self._decode(serialized_object)
        # TODO: restore behavior
        # self._validate_coded()
        return self

    def _decode(self, dict_object):
        raise NotImplementedError()

    def warnings(self):
        warns = list(self.__warnings__)
        if "2.7" in platform.python_version().rsplit(".", 1)[0]:
            del self.__warnings__[:]
        else:
            self.__warnings__.clear()
        return warns


class OpenApiValidator(object):

    __slots__ = ()

    _validation_errors = []

    def __init__(self):
        pass

    def _clear_errors(self):
        if "2.7" in platform.python_version().rsplit(".", 1)[0]:
            del self._validation_errors[:]
        else:
            self._validation_errors.clear()

    def validate_mac(self, mac):
        if mac is None or not isinstance(mac, (str, unicode)) or mac.count(" ") != 0:
            return False
        try:
            if len(mac) != 17:
                return False
            return all([0 <= int(oct, 16) <= 255 for oct in mac.split(":")])
        except Exception:
            return False

    def validate_ipv4(self, ip):
        if ip is None or not isinstance(ip, (str, unicode)) or ip.count(" ") != 0:
            return False
        if len(ip.split(".")) != 4:
            return False
        try:
            return all([0 <= int(oct) <= 255 for oct in ip.split(".", 3)])
        except Exception:
            return False

    def validate_ipv6(self, ip):
        if ip is None or not isinstance(ip, (str, unicode)):
            return False
        ip = ip.strip()
        if (
            ip.count(" ") > 0
            or ip.count(":") > 7
            or ip.count("::") > 1
            or ip.count(":::") > 0
        ):
            return False
        if (ip[0] == ":" and ip[:2] != "::") or (ip[-1] == ":" and ip[-2:] != "::"):
            return False
        if ip.count("::") == 0 and ip.count(":") != 7:
            return False
        if ip == "::":
            return True
        if ip[:2] == "::":
            ip = ip.replace("::", "0:")
        elif ip[-2:] == "::":
            ip = ip.replace("::", ":0")
        else:
            ip = ip.replace("::", ":0:")
        try:
            return all(
                [
                    True
                    if (0 <= int(oct, 16) <= 65535) and (1 <= len(oct) <= 4)
                    else False
                    for oct in ip.split(":")
                ]
            )
        except Exception:
            return False

    def validate_hex(self, hex):
        if hex is None or not isinstance(hex, (str, unicode)):
            return False
        try:
            int(hex, 16)
            return True
        except Exception:
            return False

    def validate_integer(self, value, min, max, type_format=None):
        if value is None or not isinstance(value, int):
            return False
        if min is not None and value < min:
            return False
        if max is not None and value > max:
            return False
        if type_format is not None:
            if type_format == "uint32" and (value < 0 or value > 4294967295):
                return False
            elif type_format == "uint64" and (
                value < 0 or value > 18446744073709551615
            ):
                return False
            elif type_format == "int32" and (value < -2147483648 or value > 2147483647):
                return False
            elif type_format == "int64" and (
                value < -9223372036854775808 or value > 9223372036854775807
            ):
                return False
        return True

    def validate_float(self, value):
        return isinstance(value, (int, float))

    def validate_string(self, value, min_length, max_length):
        if value is None or not isinstance(value, (str, unicode)):
            return False
        if min_length is not None and len(value) < min_length:
            return False
        if max_length is not None and len(value) > max_length:
            return False
        return True

    def validate_bool(self, value):
        return isinstance(value, bool)

    def validate_list(self, value, itemtype, min, max, min_length, max_length):
        if value is None or not isinstance(value, list):
            return False
        v_obj = getattr(self, "validate_{}".format(itemtype), None)
        if v_obj is None:
            raise AttributeError("{} is not a valid attribute".format(itemtype))
        v_obj_lst = []
        for item in value:
            if itemtype == "integer":
                v_obj_lst.append(v_obj(item, min, max))
            elif itemtype == "string":
                v_obj_lst.append(v_obj(item, min_length, max_length))
            else:
                v_obj_lst.append(v_obj(item))
        return v_obj_lst

    def validate_binary(self, value):
        if value is None or not isinstance(value, (str, unicode)):
            return False
        return all([True if int(bin) == 0 or int(bin) == 1 else False for bin in value])

    def types_validation(
        self,
        value,
        type_,
        err_msg,
        itemtype=None,
        min=None,
        max=None,
        min_length=None,
        max_length=None,
    ):
        type_map = {
            int: "integer",
            str: "string",
            float: "float",
            bool: "bool",
            list: "list",
            "int64": "integer",
            "int32": "integer",
            "uint64": "integer",
            "uint32": "integer",
            "double": "float",
        }
        type_format = type_
        if type_ in type_map:
            type_ = type_map[type_]
        if itemtype is not None and itemtype in type_map:
            itemtype = type_map[itemtype]
        v_obj = getattr(self, "validate_{}".format(type_), None)
        if v_obj is None:
            msg = "{} is not a valid or unsupported format".format(type_)
            raise TypeError(msg)
        if type_ == "list":
            verdict = v_obj(value, itemtype, min, max, min_length, max_length)
            if all(verdict) is True:
                return
            err_msg = "{} \n {} are not valid".format(
                err_msg,
                [value[index] for index, item in enumerate(verdict) if item is False],
            )
            verdict = False
        elif type_ == "integer":
            verdict = v_obj(value, min, max, type_format)
            if verdict is True:
                return
            min_max = ""
            if min is not None:
                min_max = ", expected min {}".format(min)
            if max is not None:
                min_max = min_max + ", expected max {}".format(max)
            err_msg = "{} \n got {} of type {} {}".format(
                err_msg, value, type(value), min_max
            )
        elif type_ == "string":
            verdict = v_obj(value, min_length, max_length)
            if verdict is True:
                return
            msg = ""
            if min_length is not None:
                msg = ", expected min {}".format(min_length)
            if max_length is not None:
                msg = msg + ", expected max {}".format(max_length)
            err_msg = "{} \n got {} of type {} {}".format(
                err_msg, value, type(value), msg
            )
        else:
            verdict = v_obj(value)
        if verdict is False:
            raise TypeError(err_msg)

    def _validate_unique_and_name(self, name, value, latter=False):
        if self._TYPES[name].get("unique") is None or value is None:
            return
        if latter is True:
            self.__validate_latter__["unique"].append(
                (self._validate_unique_and_name, name, value)
            )
            return
        class_name = type(self).__name__
        unique_type = self._TYPES[name]["unique"]
        if class_name not in self.__constraints__:
            self.__constraints__[class_name] = dict()
        if unique_type == "global":
            values = self.__constraints__["global"]
        else:
            values = self.__constraints__[class_name]
        if value in values:
            self._validation_errors.append(
                "{} with {} already exists".format(name, value)
            )
            return
        if isinstance(values, list):
            values.append(value)
        self.__constraints__[class_name].update({value: self})

    def _validate_constraint(self, name, value, latter=False):
        cons = self._TYPES[name].get("constraint")
        if cons is None or value is None:
            return
        if latter is True:
            self.__validate_latter__["constraint"].append(
                (self._validate_constraint, name, value)
            )
            return
        found = False
        for c in cons:
            klass, prop = c.split(".")
            names = self.__constraints__.get(klass, {})
            props = [obj._properties.get(prop) for obj in names.values()]
            if value in props:
                found = True
                break
        if found is not True:
            self._validation_errors.append(
                "{} is not a valid type of {}".format(value, "||".join(cons))
            )
            return

    def _validate_coded(self):
        for item in self.__validate_latter__["unique"]:
            item[0](item[1], item[2])
        for item in self.__validate_latter__["constraint"]:
            item[0](item[1], item[2])
        self._clear_vars()
        if len(self._validation_errors) > 0:
            errors = "\n".join(self._validation_errors)
            self._clear_errors()
            raise Exception(errors)

    def _clear_vars(self):
        if platform.python_version_tuple()[0] == "2":
            self.__validate_latter__["unique"] = []
            self.__validate_latter__["constraint"] = []
        else:
            self.__validate_latter__["unique"].clear()
            self.__validate_latter__["constraint"].clear()

    def _clear_globals(self):
        keys = list(self.__constraints__.keys())
        for k in keys:
            if k == "global":
                self.__constraints__["global"] = []
                continue
            del self.__constraints__[k]


class OpenApiObject(OpenApiBase, OpenApiValidator):
    """Base class for any /components/schemas object

    Every OpenApiObject is reuseable within the schema so it can
    exist in multiple locations within the hierarchy.
    That means it can exist in multiple locations as a
    leaf, parent/choice or parent.
    """

    __slots__ = ("__warnings__", "_properties", "_parent", "_choice")
    _DEFAULTS = {}
    _TYPES = {}
    _REQUIRED = []
    _STATUS = {}

    def __init__(self, parent=None, choice=None):
        super(OpenApiObject, self).__init__()
        self._parent = parent
        self._choice = choice
        self._properties = {}
        self.__warnings__ = []

    @property
    def parent(self):
        return self._parent

    def _set_choice(self, name):
        if self._has_choice(name):
            for enum in self._TYPES["choice"]["enum"]:
                if enum in self._properties and name != enum:
                    self._properties.pop(enum)
            self._properties["choice"] = name

    def _has_choice(self, name):
        if (
            "choice" in dir(self)
            and "_TYPES" in dir(self)
            and "choice" in self._TYPES
            and name in self._TYPES["choice"]["enum"]
        ):
            return True
        else:
            return False

    def _get_property(self, name, default_value=None, parent=None, choice=None):
        if name in self._properties and self._properties[name] is not None:
            return self._properties[name]
        if isinstance(default_value, type) is True:
            self._set_choice(name)
            if "_choice" in default_value.__slots__:
                self._properties[name] = default_value(parent=parent, choice=choice)
            else:
                self._properties[name] = default_value(parent=parent)
            if (
                "_DEFAULTS" in dir(self._properties[name])
                and "choice" in self._properties[name]._DEFAULTS
            ):
                getattr(
                    self._properties[name],
                    self._properties[name]._DEFAULTS["choice"],
                )
        else:
            if default_value is None and name in self._DEFAULTS:
                self._set_choice(name)
                self._properties[name] = self._DEFAULTS[name]
            else:
                self._properties[name] = default_value
        return self._properties[name]

    def _set_property(self, name, value, choice=None):
        if name == "choice":

            if (
                self.parent is None
                and value is not None
                and value not in self._TYPES["choice"]["enum"]
            ):
                raise Exception(
                    "%s is not a valid choice, valid choices are %s"
                    % (value, ", ".join(self._TYPES["choice"]["enum"]))
                )

            self._set_choice(value)
            if name in self._DEFAULTS and value is None:
                self._properties[name] = self._DEFAULTS[name]
        elif name in self._DEFAULTS and value is None:
            self._set_choice(name)
            self._properties[name] = self._DEFAULTS[name]
        else:
            self._set_choice(name)
            self._properties[name] = value
        # TODO: restore behavior
        # self._validate_unique_and_name(name, value)
        # self._validate_constraint(name, value)
        if self._parent is not None and self._choice is not None and value is not None:
            self._parent._set_property("choice", self._choice)

    def _encode(self):
        """Helper method for serialization"""
        output = {}
        self._raise_status_warnings(self, None)
        self._validate_required()
        for key, value in self._properties.items():
            self._validate_types(key, value)
            # TODO: restore behavior
            # self._validate_unique_and_name(key, value, True)
            # self._validate_constraint(key, value, True)
            if isinstance(value, (OpenApiObject, OpenApiIter)):
                output[key] = value._encode()
                if isinstance(value, OpenApiObject):
                    self._raise_status_warnings(key, value)
            elif value is not None:
                if (
                    self._TYPES.get(key, {}).get("format", "") == "int64"
                    or self._TYPES.get(key, {}).get("format", "") == "uint64"
                ):
                    value = str(value)
                elif (
                    self._TYPES.get(key, {}).get("itemformat", "") == "int64"
                    or self._TYPES.get(key, {}).get("itemformat", "") == "uint64"
                ):
                    value = [str(v) for v in value]
                output[key] = value
                self._raise_status_warnings(key, value)
        return output

    def _decode(self, obj):
        dtypes = [list, str, int, float, bool]
        self._raise_status_warnings(self, None)
        for property_name, property_value in obj.items():
            if property_name in self._TYPES:
                ignore_warnings = False
                if isinstance(property_value, dict):
                    child = self._get_child_class(property_name)
                    if "choice" in child[1]._TYPES and "_parent" in child[1].__slots__:
                        property_value = child[1](self, property_name)._decode(
                            property_value
                        )
                    elif "_parent" in child[1].__slots__:
                        property_value = child[1](self)._decode(property_value)
                    else:
                        property_value = child[1]()._decode(property_value)
                elif (
                    isinstance(property_value, list)
                    and property_name in self._TYPES
                    and self._TYPES[property_name]["type"] not in dtypes
                ):
                    child = self._get_child_class(property_name, True)
                    openapi_list = child[0]()
                    for item in property_value:
                        item = child[1]()._decode(item)
                        openapi_list._items.append(item)
                    property_value = openapi_list
                    ignore_warnings = True
                elif property_name in self._DEFAULTS and property_value is None:
                    if isinstance(self._DEFAULTS[property_name], tuple(dtypes)):
                        property_value = self._DEFAULTS[property_name]
                self._set_choice(property_name)
                # convert int64(will be string on wire) to to int
                if (
                    self._TYPES[property_name].get("format", "") == "int64"
                    or self._TYPES[property_name].get("format", "") == "uint64"
                ):
                    property_value = int(property_value)
                elif (
                    self._TYPES[property_name].get("itemformat", "") == "int64"
                    or self._TYPES[property_name].get("itemformat", "") == "uint64"
                ):
                    property_value = [int(v) for v in property_value]
                self._properties[property_name] = property_value
                # TODO: restore behavior
                # OpenApiStatus.warn(
                #     "{}.{}".format(type(self).__name__, property_name), self
                # )
                if not ignore_warnings:
                    self._raise_status_warnings(property_name, property_value)
            self._validate_types(property_name, property_value)
            # TODO: restore behavior
            # self._validate_unique_and_name(property_name, property_value, True)
            # self._validate_constraint(property_name, property_value, True)
        self._validate_required()
        return self

    def _get_child_class(self, property_name, is_property_list=False):
        list_class = None
        class_name = self._TYPES[property_name]["type"]
        module = globals().get(self.__module__)
        if module is None:
            module = importlib.import_module(self.__module__)
            globals()[self.__module__] = module
        object_class = getattr(module, class_name)
        if is_property_list is True:
            list_class = object_class
            object_class = getattr(module, class_name[0:-4])
        return (list_class, object_class)

    def __str__(self):
        return self.serialize(encoding=self.YAML)

    def __deepcopy__(self, memo):
        """Creates a deep copy of the current object"""
        return self.__class__().deserialize(self.serialize())

    def __copy__(self):
        """Creates a deep copy of the current object"""
        return self.__deepcopy__(None)

    def __eq__(self, other):
        return self.__str__() == other.__str__()

    def clone(self):
        """Creates a deep copy of the current object"""
        return self.__deepcopy__(None)

    def _validate_required(self):
        """Validates the required properties are set
        Use getattr as it will set any defaults prior to validating
        """
        if getattr(self, "_REQUIRED", None) is None:
            return
        for name in self._REQUIRED:
            if self._properties.get(name) is None:
                msg = (
                    "{} is a mandatory property of {}"
                    " and should not be set to None".format(
                        name,
                        self.__class__,
                    )
                )
                raise ValueError(msg)

    def _validate_types(self, property_name, property_value):
        common_data_types = [list, str, int, float, bool]
        if property_name not in self._TYPES:
            # raise ValueError("Invalid Property {}".format(property_name))
            return
        details = self._TYPES[property_name]
        if (
            property_value is None
            and property_name not in self._DEFAULTS
            and property_name not in self._REQUIRED
        ):
            return
        if "enum" in details and property_value not in details["enum"]:
            raise_error = False
            if isinstance(property_value, list):
                for value in property_value:
                    if value not in details["enum"]:
                        raise_error = True
                        break
            elif property_value not in details["enum"]:
                raise_error = True

            if raise_error is True:
                msg = "property {} shall be one of these" " {} enum, but got {} at {}"
                raise TypeError(
                    msg.format(
                        property_name,
                        details["enum"],
                        property_value,
                        self.__class__,
                    )
                )
        if details["type"] in common_data_types and "format" not in details:
            msg = "property {} shall be of type {} at {}".format(
                property_name, details["type"], self.__class__
            )

            itemtype = (
                details.get("itemformat")
                if "itemformat" in details
                else details.get("itemtype")
            )
            self.types_validation(
                property_value,
                details["type"],
                msg,
                itemtype,
                details.get("minimum"),
                details.get("maximum"),
                details.get("minLength"),
                details.get("maxLength"),
            )

        if details["type"] not in common_data_types:
            class_name = details["type"]
            # TODO Need to revisit importlib
            module = importlib.import_module(self.__module__)
            object_class = getattr(module, class_name)
            if not isinstance(property_value, object_class):
                msg = "property {} shall be of type {}," " but got {} at {}"
                raise TypeError(
                    msg.format(
                        property_name,
                        class_name,
                        type(property_value),
                        self.__class__,
                    )
                )
        if "format" in details:
            msg = "Invalid {} format, expected {} at {}".format(
                property_value, details["format"], self.__class__
            )
            _type = details["type"] if details["type"] is list else details["format"]
            self.types_validation(
                property_value,
                _type,
                msg,
                details["format"],
                details.get("minimum"),
                details.get("maximum"),
                details.get("minLength"),
                details.get("maxLength"),
            )

    def validate(self):
        self._validate_required()
        for key, value in self._properties.items():
            self._validate_types(key, value)
        # TODO: restore behavior
        # self._validate_coded()

    def get(self, name, with_default=False):
        """
        getattr for openapi object
        """
        if self._properties.get(name) is not None:
            return self._properties[name]
        elif with_default:
            # TODO need to find a way to avoid getattr
            choice = self._properties.get("choice") if "choice" in dir(self) else None
            getattr(self, name)
            if "choice" in dir(self):
                if choice is None and "choice" in self._properties:
                    self._properties.pop("choice")
                else:
                    self._properties["choice"] = choice
            return self._properties.pop(name)
        return None

    def _raise_status_warnings(self, property_name, property_value):
        if len(self._STATUS) > 0:

            if isinstance(property_name, OpenApiObject):
                if "self" in self._STATUS and property_value is None:
                    print("[WARNING]: %s" % self._STATUS["self"])

                return

            enum_key = "%s.%s" % (property_name, property_value)
            if property_name in self._STATUS:
                print("[WARNING]: %s" % self._STATUS[property_name])
            elif enum_key in self._STATUS:
                print("[WARNING]: %s" % self._STATUS[enum_key])


class OpenApiIter(OpenApiBase):
    """Container class for OpenApiObject

    Inheriting classes contain 0..n instances of an OpenAPI components/schemas
    object.
    - config.flows.flow(name="1").flow(name="2").flow(name="3")

    The __getitem__ method allows getting an instance using ordinal.
    - config.flows[0]
    - config.flows[1:]
    - config.flows[0:1]
    - f1, f2, f3 = config.flows

    The __iter__ method allows for iterating across the encapsulated contents
    - for flow in config.flows:
    """

    __slots__ = ("_index", "_items")
    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self):
        super(OpenApiIter, self).__init__()
        self._index = -1
        self._items = []

    def __len__(self):
        return len(self._items)

    def _getitem(self, key):
        found = None
        if isinstance(key, int):
            found = self._items[key]
        elif isinstance(key, slice) is True:
            start, stop, step = key.indices(len(self))
            sliced = self.__class__()
            for i in range(start, stop, step):
                sliced._items.append(self._items[i])
            return sliced
        elif isinstance(key, str):
            for item in self._items:
                if item.name == key:
                    found = item
        if found is None:
            raise IndexError()
        if (
            self._GETITEM_RETURNS_CHOICE_OBJECT is True
            and found._properties.get("choice") is not None
            and found._properties.get(found._properties["choice"]) is not None
        ):
            return found._properties[found._properties["choice"]]
        return found

    def _iter(self):
        self._index = -1
        return self

    def _next(self):
        if self._index + 1 >= len(self._items):
            raise StopIteration
        else:
            self._index += 1
        return self.__getitem__(self._index)

    def __getitem__(self, key):
        raise NotImplementedError("This should be overridden by the generator")

    def _add(self, item):
        self._items.append(item)
        self._index = len(self._items) - 1

    def remove(self, index):
        del self._items[index]
        self._index = len(self._items) - 1

    def append(self, item):
        """Append an item to the end of OpenApiIter
        TBD: type check, raise error on mismatch
        """
        self._instanceOf(item)
        self._add(item)
        return self

    def clear(self):
        del self._items[:]
        self._index = -1

    def set(self, index, item):
        self._instanceOf(item)
        self._items[index] = item
        return self

    def _encode(self):
        return [item._encode() for item in self._items]

    def _decode(self, encoded_list):
        item_class_name = self.__class__.__name__.replace("Iter", "")
        module = importlib.import_module(self.__module__)
        object_class = getattr(module, item_class_name)
        self.clear()
        for item in encoded_list:
            self._add(object_class()._decode(item))

    def __copy__(self):
        raise NotImplementedError(
            "Shallow copy of OpenApiIter objects is not supported"
        )

    def __deepcopy__(self, memo):
        raise NotImplementedError("Deep copy of OpenApiIter objects is not supported")

    def __str__(self):
        return yaml.safe_dump(self._encode())

    def __eq__(self, other):
        return self.__str__() == other.__str__()

    def _instanceOf(self, item):
        raise NotImplementedError("validating an OpenApiIter object is not supported")


class Config(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "links": {"type": "LinkIter"},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None):
        super(Config, self).__init__()
        self._parent = parent

    @property
    def links(self):
        # type: () -> LinkIter
        """links getter

        Connection between ports within switch.

        Returns: LinkIter
        """
        return self._get_property("links", LinkIter, self._parent, self._choice)


class Link(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "src": {"type": str},
        "dst": {"type": str},
        "mode": {
            "type": str,
            "enum": [
                "unidirectional",
                "bidirectional",
            ],
        },
    }  # type: Dict[str, str]

    _REQUIRED = ("src", "dst")  # type: tuple(str)

    _DEFAULTS = {
        "mode": "bidirectional",
    }  # type: Dict[str, Union(type)]

    UNIDIRECTIONAL = "unidirectional"  # type: str
    BIDIRECTIONAL = "bidirectional"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, src=None, dst=None, mode="bidirectional"):
        super(Link, self).__init__()
        self._parent = parent
        self._set_property("src", src)
        self._set_property("dst", dst)
        self._set_property("mode", mode)

    def set(self, src=None, dst=None, mode=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def src(self):
        # type: () -> str
        """src getter

        Src for the link.

        Returns: str
        """
        return self._get_property("src")

    @src.setter
    def src(self, value):
        """src setter

        Src for the link.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property src as None")
        self._set_property("src", value)

    @property
    def dst(self):
        # type: () -> str
        """dst getter

        Dst of the link.

        Returns: str
        """
        return self._get_property("dst")

    @dst.setter
    def dst(self, value):
        """dst setter

        Dst of the link.

        value: str
        """
        if value is None:
            raise TypeError("Cannot set required property dst as None")
        self._set_property("dst", value)

    @property
    def mode(self):
        # type: () -> Union[Literal["bidirectional"], Literal["unidirectional"]]
        """mode getter

        TBD

        Returns: Union[Literal["bidirectional"], Literal["unidirectional"]]
        """
        return self._get_property("mode")

    @mode.setter
    def mode(self, value):
        """mode setter

        TBD

        value: Union[Literal["bidirectional"], Literal["unidirectional"]]
        """
        self._set_property("mode", value)


class LinkIter(OpenApiIter):
    __slots__ = ("_parent", "_choice")

    _GETITEM_RETURNS_CHOICE_OBJECT = False

    def __init__(self, parent=None, choice=None):
        super(LinkIter, self).__init__()
        self._parent = parent
        self._choice = choice

    def __getitem__(self, key):
        # type: (str) -> Union[Link]
        return self._getitem(key)

    def __iter__(self):
        # type: () -> LinkIter
        return self._iter()

    def __next__(self):
        # type: () -> Link
        return self._next()

    def next(self):
        # type: () -> Link
        return self._next()

    def _instanceOf(self, item):
        if not isinstance(item, Link):
            raise Exception("Item is not an instance of Link")

    def link(self, src=None, dst=None, mode="bidirectional"):
        # type: (str,str,Union[Literal["bidirectional"], Literal["unidirectional"]]) -> LinkIter
        """Factory method that creates an instance of the Link class

        Link between the Ports.

        Returns: LinkIter
        """
        item = Link(parent=self._parent, src=src, dst=dst, mode=mode)
        self._add(item)
        return self

    def add(self, src=None, dst=None, mode="bidirectional"):
        # type: (str,str,Union[Literal["bidirectional"], Literal["unidirectional"]]) -> Link
        """Add method that creates and returns an instance of the Link class

        Link between the Ports.

        Returns: Link
        """
        item = Link(parent=self._parent, src=src, dst=dst, mode=mode)
        self._add(item)
        return item


class Error(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "code": {
            "type": int,
            "format": "int32",
        },
        "kind": {
            "type": str,
            "enum": [
                "validation",
                "internal",
            ],
        },
        "errors": {
            "type": list,
            "itemtype": str,
        },
    }  # type: Dict[str, str]

    _REQUIRED = ("code", "errors")  # type: tuple(str)

    _DEFAULTS = {}  # type: Dict[str, Union(type)]

    VALIDATION = "validation"  # type: str
    INTERNAL = "internal"  # type: str

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(self, parent=None, code=None, kind=None, errors=None):
        super(Error, self).__init__()
        self._parent = parent
        self._set_property("code", code)
        self._set_property("kind", kind)
        self._set_property("errors", errors)

    def set(self, code=None, kind=None, errors=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def code(self):
        # type: () -> int
        """code getter

        Numeric status code based on the underlying transport being used.. The API server MUST set this code explicitly based on following references:. HTTP 4xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.5. HTTP 5xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6. gRPC errors: https://grpc.github.io/grpc/core/md_doc_statuscodes.html

        Returns: int
        """
        return self._get_property("code")

    @code.setter
    def code(self, value):
        """code setter

        Numeric status code based on the underlying transport being used.. The API server MUST set this code explicitly based on following references:. HTTP 4xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.5. HTTP 5xx errors: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6. gRPC errors: https://grpc.github.io/grpc/core/md_doc_statuscodes.html

        value: int
        """
        if value is None:
            raise TypeError("Cannot set required property code as None")
        self._set_property("code", value)

    @property
    def kind(self):
        # type: () -> Union[Literal["internal"], Literal["validation"]]
        """kind getter

        Classification of error originating from within API server that may not be mapped to the value in `code`.. Absence of this field may indicate that the error did not originate from within API server.

        Returns: Union[Literal["internal"], Literal["validation"]]
        """
        return self._get_property("kind")

    @kind.setter
    def kind(self, value):
        """kind setter

        Classification of error originating from within API server that may not be mapped to the value in `code`.. Absence of this field may indicate that the error did not originate from within API server.

        value: Union[Literal["internal"], Literal["validation"]]
        """
        self._set_property("kind", value)

    @property
    def errors(self):
        # type: () -> List[str]
        """errors getter

        List of error messages generated while executing the request.

        Returns: List[str]
        """
        return self._get_property("errors")

    @errors.setter
    def errors(self, value):
        """errors setter

        List of error messages generated while executing the request.

        value: List[str]
        """
        if value is None:
            raise TypeError("Cannot set required property errors as None")
        self._set_property("errors", value)


class Version(OpenApiObject):
    __slots__ = "_parent"

    _TYPES = {
        "api_spec_version": {"type": str},
        "sdk_version": {"type": str},
        "app_version": {"type": str},
    }  # type: Dict[str, str]

    _REQUIRED = ()  # type: tuple(str)

    _DEFAULTS = {
        "api_spec_version": "",
        "sdk_version": "",
        "app_version": "",
    }  # type: Dict[str, Union(type)]

    _STATUS = {}  # type: Dict[str, Union(type)]

    def __init__(
        self, parent=None, api_spec_version="", sdk_version="", app_version=""
    ):
        super(Version, self).__init__()
        self._parent = parent
        self._set_property("api_spec_version", api_spec_version)
        self._set_property("sdk_version", sdk_version)
        self._set_property("app_version", app_version)

    def set(self, api_spec_version=None, sdk_version=None, app_version=None):
        for property_name, property_value in locals().items():
            if property_name != "self" and property_value is not None:
                self._set_property(property_name, property_value)

    @property
    def api_spec_version(self):
        # type: () -> str
        """api_spec_version getter

        Version of API specification

        Returns: str
        """
        return self._get_property("api_spec_version")

    @api_spec_version.setter
    def api_spec_version(self, value):
        """api_spec_version setter

        Version of API specification

        value: str
        """
        self._set_property("api_spec_version", value)

    @property
    def sdk_version(self):
        # type: () -> str
        """sdk_version getter

        Version of SDK generated from API specification

        Returns: str
        """
        return self._get_property("sdk_version")

    @sdk_version.setter
    def sdk_version(self, value):
        """sdk_version setter

        Version of SDK generated from API specification

        value: str
        """
        self._set_property("sdk_version", value)

    @property
    def app_version(self):
        # type: () -> str
        """app_version getter

        Version of application consuming or serving the API

        Returns: str
        """
        return self._get_property("app_version")

    @app_version.setter
    def app_version(self, value):
        """app_version setter

        Version of application consuming or serving the API

        value: str
        """
        self._set_property("app_version", value)


class Api(object):
    """OpenApi Abstract API"""

    __warnings__ = []

    def __init__(self, **kwargs):
        self._version_meta = self.version()
        self._version_meta.api_spec_version = "0.0.1"
        self._version_meta.sdk_version = "0.0.1"
        self._version_check = kwargs.get("version_check")
        if self._version_check is None:
            self._version_check = False
        self._version_check_err = None

    def add_warnings(self, msg):
        print("[WARNING]: %s" % msg)
        self.__warnings__.append(msg)

    def _deserialize_error(self, err_string):
        # type: (str) -> Union[Error, None]
        err = self.error()
        try:
            err.deserialize(err_string)
        except Exception:
            err = None
        return err

    def from_exception(self, error):
        # type: (Exception) -> Union[Error, None]
        if isinstance(error, Error):
            return error
        elif isinstance(error, grpc.RpcError):
            err = self._deserialize_error(error.details())
            if err is not None:
                return err
            err = self.error()
            err.code = error.code().value[0]
            err.errors = [error.details()]
            return err
        elif isinstance(error, Exception):
            if len(error.args) != 1:
                return None
            if isinstance(error.args[0], Error):
                return error.args[0]
            elif isinstance(error.args[0], str):
                return self._deserialize_error(error.args[0])

    def set_config(self, payload):
        """POST /config

        Create configuration for L1S

        Return: None
        """
        raise NotImplementedError("set_config")

    def get_version(self):
        """GET /capabilities/version

        TBD

        Return: version
        """
        raise NotImplementedError("get_version")

    def config(self):
        """Factory method that creates an instance of Config

        Return: Config
        """
        return Config()

    def error(self):
        """Factory method that creates an instance of Error

        Return: Error
        """
        return Error()

    def version(self):
        """Factory method that creates an instance of Version

        Return: Version
        """
        return Version()

    def close(self):
        pass

    def _check_client_server_version_compatibility(
        self, client_ver, server_ver, component_name
    ):
        try:
            c = semantic_version.Version(client_ver)
        except Exception as e:
            raise AssertionError(
                "Client {} version '{}' is not a valid semver: {}".format(
                    component_name, client_ver, e
                )
            )

        try:
            s = semantic_version.SimpleSpec(server_ver)
        except Exception as e:
            raise AssertionError(
                "Server {} version '{}' is not a valid semver: {}".format(
                    component_name, server_ver, e
                )
            )

        err = "Client {} version '{}' is not semver compatible with Server {} version '{}'".format(
            component_name, client_ver, component_name, server_ver
        )

        if not s.match(c):
            raise Exception(err)

    def get_local_version(self):
        return self._version_meta

    def get_remote_version(self):
        return self.get_version()

    def check_version_compatibility(self):
        comp_err, api_err = self._do_version_check()
        if comp_err is not None:
            raise comp_err
        if api_err is not None:
            raise api_err

    def _do_version_check(self):
        local = self.get_local_version()
        try:
            remote = self.get_remote_version()
        except Exception as e:
            return None, e

        try:
            self._check_client_server_version_compatibility(
                local.api_spec_version, remote.api_spec_version, "API spec"
            )
        except Exception as e:
            msg = "client SDK version '{}' is not compatible with server SDK version '{}'".format(
                local.sdk_version, remote.sdk_version
            )
            return Exception("{}: {}".format(msg, str(e))), None

        return None, None

    def _do_version_check_once(self):
        if not self._version_check:
            return

        if self._version_check_err is not None:
            raise self._version_check_err

        comp_err, api_err = self._do_version_check()
        if comp_err is not None:
            self._version_check_err = comp_err
            raise comp_err
        if api_err is not None:
            self._version_check_err = None
            raise api_err

        self._version_check = False
        self._version_check_err = None


class HttpApi(Api):
    """OpenAPI HTTP Api"""

    def __init__(self, **kwargs):
        super(HttpApi, self).__init__(**kwargs)
        self._transport = HttpTransport(**kwargs)

    @property
    def verify(self):
        return self._transport.verify

    @verify.setter
    def verify(self, value):
        self._transport.set_verify(value)

    def set_config(self, payload):
        """POST /config

        Create configuration for L1S

        Return: None
        """
        self._do_version_check_once()
        return self._transport.send_recv(
            "post",
            "/config",
            payload=payload,
            return_object=None,
            request_class=Config,
        )

    def get_version(self):
        """GET /capabilities/version

        TBD

        Return: version
        """
        return self._transport.send_recv(
            "get",
            "/capabilities/version",
            payload=None,
            return_object=self.version(),
        )


class GrpcApi(Api):
    # OpenAPI gRPC Api
    def __init__(self, **kwargs):
        super(GrpcApi, self).__init__(**kwargs)
        self._stub = None
        self._channel = None
        self._cert = None
        self._cert_domain = None
        self._request_timeout = 10
        self._keep_alive_timeout = 10 * 1000
        self._location = (
            kwargs["location"]
            if "location" in kwargs and kwargs["location"] is not None
            else "localhost:50051"
        )
        self._transport = kwargs["transport"] if "transport" in kwargs else None
        self._logger = kwargs["logger"] if "logger" in kwargs else None
        self._loglevel = kwargs["loglevel"] if "loglevel" in kwargs else logging.DEBUG
        if self._logger is None:
            stdout_handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                fmt="%(asctime)s [%(name)s] [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            formatter.converter = time.gmtime
            stdout_handler.setFormatter(formatter)
            self._logger = logging.Logger(self.__module__, level=self._loglevel)
            self._logger.addHandler(stdout_handler)
        self._logger.debug(
            "gRPCTransport args: {}".format(
                ", ".join(["{}={!r}".format(k, v) for k, v in kwargs.items()])
            )
        )

    def _use_secure_connection(self, cert_path, cert_domain=None):
        """Accepts certificate and host_name for SSL Connection."""
        if cert_path is None:
            raise Exception("path to certificate cannot be None")
        self._cert = cert_path
        self._cert_domain = cert_domain

    def _get_stub(self):
        if self._stub is None:
            CHANNEL_OPTIONS = [
                ("grpc.enable_retries", 0),
                ("grpc.keepalive_timeout_ms", self._keep_alive_timeout),
            ]
            if self._cert is None:
                self._channel = grpc.insecure_channel(
                    self._location, options=CHANNEL_OPTIONS
                )
            else:
                crt = open(self._cert, "rb").read()
                creds = grpc.ssl_channel_credentials(crt)
                if self._cert_domain is not None:
                    CHANNEL_OPTIONS.append(
                        ("grpc.ssl_target_name_override", self._cert_domain)
                    )
                self._channel = grpc.secure_channel(
                    self._location, credentials=creds, options=CHANNEL_OPTIONS
                )
            self._stub = pb2_grpc.OpenapiStub(self._channel)
        return self._stub

    def _serialize_payload(self, payload):
        if not isinstance(payload, (str, dict, OpenApiBase)):
            raise Exception("We are supporting [str, dict, OpenApiBase] object")
        if isinstance(payload, OpenApiBase):
            payload = payload.serialize()
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        elif isinstance(payload, (str, unicode)):
            payload = json.dumps(yaml.safe_load(payload))
        return payload

    def _raise_exception(self, grpc_error):
        err = self.error()
        try:
            err.deserialize(grpc_error.details())
        except Exception as _:
            err.code = grpc_error.code().value[0]
            err.errors = [grpc_error.details()]
        raise Exception(err)

    @property
    def request_timeout(self):
        """duration of time in seconds to allow for the RPC."""
        return self._request_timeout

    @request_timeout.setter
    def request_timeout(self, timeout):
        self._request_timeout = timeout

    @property
    def keep_alive_timeout(self):
        return self._keep_alive_timeout

    @keep_alive_timeout.setter
    def keep_alive_timeout(self, timeout):
        self._keep_alive_timeout = timeout * 1000

    def close(self):
        if self._channel is not None:
            self._channel.close()
            self._channel = None
            self._stub = None

    def set_config(self, payload):
        pb_obj = json_format.Parse(self._serialize_payload(payload), pb2.Config())
        self._do_version_check_once()
        req_obj = pb2.SetConfigRequest(config=pb_obj)
        stub = self._get_stub()
        try:
            res_obj = stub.SetConfig(req_obj, timeout=self._request_timeout)
        except grpc.RpcError as grpc_error:
            self._raise_exception(grpc_error)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        resp_str = response.get("string")
        if resp_str is not None:
            return response.get("string")

    def get_version(self):
        stub = self._get_stub()
        empty = pb2_grpc.google_dot_protobuf_dot_empty__pb2.Empty()
        res_obj = stub.GetVersion(empty, timeout=self._request_timeout)
        response = json_format.MessageToDict(res_obj, preserving_proto_field_name=True)
        result = response.get("version")
        if result is not None:
            return self.version().deserialize(result)
