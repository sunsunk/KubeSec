#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2020-2023 Alibaba Group Holding Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import logging
import os
import textwrap

from .parsing import check_class
from .parsing import find_distributed_field
from .parsing import find_fields
from .parsing import generate_template_header
from .parsing import generate_template_type
from .parsing import parse_codegen_spec_from_type
from .parsing import split_members_and_methods

###############################################################################
#
# codegen the `Create` static method
#

create_tpl = '''
{class_header}
std::unique_ptr<Object> {class_name_elaborated}::Create() {{
    return std::static_pointer_cast<Object>(
        std::unique_ptr<{class_name_elaborated}>{{
            new {class_name_elaborated}()}});
}}
'''

create_meth_tpl = '''
  public:
    static std::unique_ptr<Object> Create() __attribute__((used)) {{
        return std::static_pointer_cast<Object>(
            std::unique_ptr<{class_name_elaborated}>{{
                new {class_name_elaborated}()}});
    }}
'''


def codegen_create(class_header, class_name, class_name_elaborated, meth=False):
    if meth:
        function_tpl = create_meth_tpl
    else:
        function_tpl = create_tpl

    return function_tpl.format(
        class_header=class_header,
        class_name=class_name,
        class_name_elaborated=class_name_elaborated,
    )


###############################################################################
#
# codegen the `Construct` method
#

construct_tpl = '''
{class_header}
void {class_name_elaborated}::Construct(const ObjectMeta &meta) {{
    std::string __type_name = type_name<{class_name_elaborated}>();
    VINEYARD_ASSERT(
        meta.GetTypeName() == __type_name,
        "Expect typename '" + __type_name + "', but got '" + meta.GetTypeName() + "'");
    this->meta_ = meta;
    this->id_ = meta.GetId();

    {construct_body}

    {post_construct}
}}
'''

post_construct_tpl = '''
    if (meta.IsLocal()) {
        this->PostConstruct(meta);
    }'''

construct_meth_tpl = '''
  public:
    void Construct(const ObjectMeta& meta) override {{
        std::string __type_name = type_name<{class_name_elaborated}>();
        VINEYARD_ASSERT(
            meta.GetTypeName() == __type_name,
            "Expect typename '" + __type_name + "', but got '" + meta.GetTypeName() + "'");
        Object::Construct(meta);

        {construct_body}

        {post_construct}
    }}
'''

post_construct_meth_tpl = '''
        if (meta.IsLocal()) {
            this->PostConstruct(meta);
        }'''

construct_meta_tpl = '''
    meta.GetKeyValue("{name}", this->{name});'''

construct_meta_optional_tpl = '''
    if (meta.HasKey("{name}")) {{
        meta.GetKeyValue("{name}", this->{name});
    }}'''

construct_plain_tpl = '''
    this->{name}.Construct(meta.GetMemberMeta("{name}"));'''

construct_plain_star_tpl = '''
    this->{name} = {deref}std::dynamic_pointer_cast<{element_type}>(meta.GetMember("{name}"));'''

construct_list_tpl = '''
    this->{name}.resize(meta.GetKeyValue<size_t>("__{name}-size"));
    for (size_t __idx = 0; __idx < this->{name}.size(); ++__idx) {{
        this->{name}[__idx].Construct(
            meta.GetMemberMeta("__{name}-" + std::to_string(__idx)));
    }}'''

construct_list_star_tpl = '''
    for (size_t __idx = 0; __idx < meta.GetKeyValue<size_t>("__{name}-size"); ++__idx) {{
        this->{name}.emplace_back({deref}std::dynamic_pointer_cast<{element_type}>(
                meta.GetMember("__{name}-" + std::to_string(__idx))));
    }}'''

construct_dlist_tpl = '''
    this->{name}.resize(meta.GetKeyValue<size_t>("__{name}-size"));
    for (size_t __idx = 0; __idx < this->{name}.size(); ++__idx) {{
        this->{name}[__idx].resize(meta.GetKeyValue<size_t>(
            "__{name}-" + std::to_string(__idx) + "-size"));
        for (size_t __idy = 0; __idy < this->{name}[__idx].size(); ++__idy) {{
            this->{name}[__idx][__idy].Construct(
                meta.GetMemberMeta("__{name}-" + std::to_string(__idx) + "-" + std::to_string(__idy)));
        }}
    }}'''

construct_dlist_star_tpl = '''
    this->{name}.resize(meta.GetKeyValue<size_t>("__{name}-size"));
    for (size_t __idx = 0; __idx < this->{name}.size(); ++__idx) {{
        for (size_t __idy = 0; __idy < meta.GetKeyValue<size_t>(
                "__{name}-" + std::to_string(__idx) + "-size"); ++__idy) {{
            this->{name}[__idx].emplace_back({deref}std::dynamic_pointer_cast<{element_type}>(
                meta.GetMember("__{name}-" + std::to_string(__idx) + "-" + std::to_string(__idy))));
        }}
    }}'''

construct_set_tpl = '''
    for (size_t __idx = 0; __idx < meta.GetKeyValue<size_t>("__{name}-size"); ++__idx) {{
        this->{name}.emplace({deref}std::dynamic_pointer_cast<{element_type}>(
                meta.GetMember("__{name}-" + std::to_string(__idx))));
    }}'''

construct_dict_tpl = '''
    for (size_t __idx = 0; __idx < meta.GetKeyValue<size_t>("__{name}-size"); ++__idx) {{
        this->{name}.emplace(meta.GetKeyValue<{key_type}>("__{name}-key-" + std::to_string(__idx)),
                {deref}std::dynamic_pointer_cast<{value_type}>(
                        meta.GetMember("__{name}-value-" + std::to_string(__idx))));
    }}'''


def codegen_construct(
    class_header, class_name, class_name_elaborated, fields, has_post_ctor, meth=False
):
    body = []
    for field in fields:
        spec = parse_codegen_spec_from_type(field)
        name = field.spelling
        if spec.is_meta:
            if spec.optional:
                tpl = construct_meta_optional_tpl
            else:
                tpl = construct_meta_tpl
        if spec.is_plain:
            if spec.star:
                tpl = construct_plain_star_tpl
            else:
                tpl = construct_plain_tpl
        if spec.is_list:
            if spec.star:
                tpl = construct_list_star_tpl
            else:
                tpl = construct_list_tpl
        if spec.is_dlist:
            if spec.star:
                tpl = construct_dlist_star_tpl
            else:
                tpl = construct_dlist_tpl
        if spec.is_set:
            tpl = construct_set_tpl
        if spec.is_dict:
            tpl = construct_dict_tpl

        if spec.is_dict:
            key_type = spec.element_type[0]
            value_type = spec.element_type[1]
        else:
            key_type = None
            value_type = None

        body.append(
            tpl.format(
                name=name,
                element_type=spec.element_type,
                key_type=key_type,
                value_type=value_type,
                deref=spec.deref,
            )
        )

    if meth:
        function_tpl = construct_meth_tpl
        function_body_indent = 4
        if has_post_ctor:
            post_ctor = post_construct_meth_tpl
        else:
            post_ctor = ''
    else:
        function_tpl = construct_tpl
        function_body_indent = 0
        if has_post_ctor:
            post_ctor = post_construct_tpl
        else:
            post_ctor = ''

    code = function_tpl.format(
        class_header=class_header,
        class_name=class_name,
        class_name_elaborated=class_name_elaborated,
        construct_body=textwrap.indent(
            ''.join(body), ' ' * function_body_indent
        ).strip(),
        post_construct=post_ctor,
    )
    return code


###############################################################################
#
# codegen the base builder
#

base_builder_tpl = '''
{class_header}
class {class_name}BaseBuilder{type_params}: public ObjectBuilder {{
  public:
    {using_alias}

    explicit {class_name}BaseBuilder(Client &client) {{}}

    explicit {class_name}BaseBuilder(
            {class_name_elaborated} const &__value) {{
        {get_and_assign}
    }}

    explicit {class_name}BaseBuilder(
            std::shared_ptr<{class_name_elaborated}> const & __value):
        {class_name}BaseBuilder(*__value) {{
    }}

    ObjectMeta &ValueMetaRef(std::shared_ptr<{class_name_elaborated}> &__value) {{
        return __value->meta_;
    }}

    Status _Seal(Client& client, std::shared_ptr<Object>& object) override {{
        // ensure the builder hasn't been sealed yet.
        ENSURE_NOT_SEALED(this);

        RETURN_ON_ERROR(this->Build(client));
        auto __value = std::make_shared<{class_name_elaborated}>();
        object = __value;

        size_t __value_nbytes = 0;

        __value->meta_.SetTypeName(type_name<{class_name_elaborated}>());

        {assignments}

        __value->meta_.SetNBytes(__value_nbytes);

        RETURN_ON_ERROR(client.CreateMetaData(__value->meta_, __value->id_));

        // mark the builder as sealed
        this->set_sealed(true);

        {post_construct}
        return Status::OK();
    }}

    Status Build(Client &client) override {{
        return Status::OK();
    }}

  protected:
    {fields_declares}

    {setters}

  private:
    friend class {class_name_elaborated};
}};
'''

field_declare_tpl = '''
    {field_type_elaborated} {field_name};'''


def codegen_field_declare(field_name, field_type, spec):
    if spec.is_meta:
        field_type_elaborated = field_type
    if spec.is_plain:
        field_type_elaborated = 'std::shared_ptr<ObjectBase>'
    if spec.is_list:
        field_type_elaborated = 'std::vector<std::shared_ptr<ObjectBase>>'
    if spec.is_dlist:
        field_type_elaborated = 'std::vector<std::vector<std::shared_ptr<ObjectBase>>>'
    if spec.is_set:
        field_type_elaborated = 'std::set<std::shared_ptr<ObjectBase>>'
    if spec.is_dict:
        field_type_elaborated = (
            'std::map<{key_type}, std::shared_ptr<ObjectBase>>'.format(
                key_type='typename %s::key_type' % field_type
            )
        )
    return field_declare_tpl.format(
        field_name=field_name, field_type_elaborated=field_type_elaborated
    )


field_assign_meta_tpl = '''
        __value->{field_name} = {field_name};
        __value->meta_.AddKeyValue("{field_name}", __value->{field_name});
'''

field_assign_meta_explicit_cast_tpl = '''
        __value->{field_name} = {field_name};
        __value->meta_.AddKeyValue("{field_name}", {value_type}(__value->{field_name}));
'''

field_assign_plain_tpl = '''
        // using __{field_name}_value_type = typename {field_type}{element_type};
        using __{field_name}_value_type = {element_type_name}decltype(__value->{field_name}){element_type};
        auto __value_{field_name} = std::dynamic_pointer_cast<__{field_name}_value_type>(
            {field_name}->_Seal(client));
        __value->{field_name} = {deref}__value_{field_name};
        __value->meta_.AddMember("{field_name}", __value->{field_name});
        __value_nbytes += __value_{field_name}->nbytes();
'''

field_assign_list_tpl = '''
        // using __{field_name}_value_type = typename {field_type}::value_type{element_type};
        using __{field_name}_value_type = typename decltype(__value->{field_name})::value_type{element_type};

        size_t __{field_name}_idx = 0;
        for (auto &__{field_name}_value: {field_name}) {{
            auto __value_{field_name} = std::dynamic_pointer_cast<__{field_name}_value_type>(
                __{field_name}_value->_Seal(client));
            __value->{field_name}.emplace_back({deref}__value_{field_name});
            __value->meta_.AddMember("__{field_name}-" + std::to_string(__{field_name}_idx),
                                     __value_{field_name});
            __value_nbytes += __value_{field_name}->nbytes();
            __{field_name}_idx += 1;
        }}
        __value->meta_.AddKeyValue("__{field_name}-size", __value->{field_name}.size());
'''

field_assign_dlist_tpl = '''
        // using __{field_name}_value_type = typename {field_type}::value_type::value_type{element_type};
        using __{field_name}_value_type = typename decltype(__value->{field_name})::value_type::value_type{element_type};

        size_t __{field_name}_idx = 0;
        __value->{field_name}.resize({field_name}.size());
        for (auto &__{field_name}_value_vec: {field_name}) {{
            size_t __{field_name}_idy = 0;
            __value->meta_.AddKeyValue("__{field_name}-" + std::to_string(__{field_name}_idx) + "-size", __{field_name}_value_vec.size());
            for (auto &__{field_name}_value: __{field_name}_value_vec) {{
                auto __value_{field_name} = std::dynamic_pointer_cast<__{field_name}_value_type>(
                    __{field_name}_value->_Seal(client));
                __value->{field_name}[__{field_name}_idx].emplace_back({deref}__value_{field_name});
                __value->meta_.AddMember("__{field_name}-" + std::to_string(__{field_name}_idx) + "-" + std::to_string(__{field_name}_idy),
                                         __value_{field_name});
                __value_nbytes += __value_{field_name}->nbytes();
                __{field_name}_idy += 1;
            }}
            __{field_name}_idx += 1;
        }}
        __value->meta_.AddKeyValue("__{field_name}-size", __value->{field_name}.size());
'''

field_assign_set_tpl = '''
        // using __{field_name}_value_type = typename {field_type}::value_type{element_type};
        using __{field_name}_value_type = typename decltype(__value->{field_name})::value_type{element_type};

        size_t __{field_name}_idx = 0;
        for (auto &__{field_name}_value: {field_name}) {{
            auto __value_{field_name} = std::dynamic_pointer_cast<__{field_name}_value_type>(
                __{field_name}_value->_Seal(client));
            __value->{field_name}.emplace({deref}__value_{field_name});
            __value->meta_.AddMember("__{field_name}-" + std::to_string(__{field_name}_idx),
                                      __value_{field_name});
            __value_nbytes += __value_{field_name}->nbytes();
            __{field_name}_idx += 1;
        }}
        __value->meta_.AddKeyValue("__{field_name}-size", __value->{field_name}.size());
'''

field_assign_dict_tpl = '''
        // using __{field_name}_value_type = typename {field_type}::mapped_type{element_type};
        using __{field_name}_value_type = typename decltype(__value->{field_name})::mapped_type{element_type};

        size_t __{field_name}_idx = 0;
        for (auto &__{field_name}_kv: {field_name}) {{
            auto __value_{field_name} = std::dynamic_pointer_cast<__{field_name}_value_type>(
                __{field_name}_kv.second->_Seal(client));
            __value->{field_name}.emplace(__{field_name}_kv.first, {deref}__value_{field_name});
            __value->meta_.AddKeyValue("__{field_name}-key-" + std::to_string(__{field_name}_idx),
                                        __{field_name}_kv.first);
            __value->meta_.AddMember("__{field_name}-value-" + std::to_string(__{field_name}_idx),
                                     __value_{field_name});
            __value_nbytes += __value_{field_name}->nbytes();
            __{field_name}_idx += 1;
        }}
        __value->meta_.AddKeyValue("__{field_name}-size", __value->{field_name}.size());
'''


def codegen_field_assign(field_name, field_type, spec):
    value_type = 'std::nullptr_t'
    if spec.is_meta:
        if field_type == 'vineyard::String':
            tpl = field_assign_meta_explicit_cast_tpl
            value_type = 'std::string'
        else:
            tpl = field_assign_meta_tpl
    if spec.is_plain:
        tpl = field_assign_plain_tpl
    if spec.is_list:
        tpl = field_assign_list_tpl
    if spec.is_dlist:
        tpl = field_assign_dlist_tpl
    if spec.is_set:
        tpl = field_assign_set_tpl
    if spec.is_dict:
        tpl = field_assign_dict_tpl
    if spec.deref:
        element_type = ''
        element_type_name = ''
    else:
        element_type = '::element_type'
        element_type_name = 'typename '
    return tpl.format(
        field_name=field_name,
        field_type=field_type,
        value_type=value_type,
        deref=spec.deref,
        element_type=element_type,
        element_type_name=element_type_name,
    )


field_setter_meta_tpl = '''
    void set_{field_name}({field_type} const &{field_name}_) {{
        this->{field_name} = {field_name}_;
    }}
'''

field_setter_plain_tpl = '''
    void set_{field_name}(std::shared_ptr<ObjectBase> const & {field_name}_) {{
        this->{field_name} = {field_name}_;
    }}
'''

field_setter_list_tpl = '''
    void set_{field_name}(std::vector<std::shared_ptr<ObjectBase>> const &{field_name}_) {{
        this->{field_name} = {field_name}_;
    }}
    void set_{field_name}(size_t const idx, std::shared_ptr<ObjectBase> const &{field_name}_) {{
        if (idx >= this->{field_name}.size()) {{
            this->{field_name}.resize(idx + 1);
        }}
        this->{field_name}[idx] = {field_name}_;
    }}
    void add_{field_name}(std::shared_ptr<ObjectBase> const &{field_name}_) {{
        this->{field_name}.emplace_back({field_name}_);
    }}
    void remove_{field_name}(const size_t {field_name}_index_) {{
        this->{field_name}.erase(this->{field_name}.begin() + {field_name}_index_);
    }}
'''

field_setter_dlist_tpl = '''
    void set_{field_name}(std::vector<std::vector<std::shared_ptr<ObjectBase>>> const &{field_name}_) {{
        this->{field_name} = {field_name}_;
    }}
    void set_{field_name}(size_t const idx, std::vector<std::shared_ptr<ObjectBase>> const &{field_name}_) {{
        if (idx >= this->{field_name}.size()) {{
            this->{field_name}.resize(idx + 1);
        }}
        this->{field_name}[idx] = {field_name}_;
    }}
    void set_{field_name}(size_t const idx, size_t const idy,
                          std::shared_ptr<ObjectBase> const &{field_name}_) {{
        if (idx >= this->{field_name}.size()) {{
            this->{field_name}.resize(idx + 1);
        }}
        if (idy >= this->{field_name}[idx].size()) {{
            this->{field_name}[idx].resize(idy + 1);
        }}
        this->{field_name}[idx][idy] = {field_name}_;
    }}
    void add_{field_name}(std::vector<std::shared_ptr<ObjectBase>> const &{field_name}_) {{
        this->{field_name}.emplace_back({field_name}_);
    }}
    void remove_{field_name}(const size_t {field_name}_index_) {{
        this->{field_name}.erase(this->{field_name}.begin() + {field_name}_index_);
    }}
    void remove_{field_name}(const size_t {field_name}_index_, const size_t {field_name}_inner_index_) {{
        auto &{field_name}_inner_ = this->{field_name}[{field_name}_index_];
        {field_name}_inner_.erase({field_name}_inner_.begin() + {field_name}_inner_index_);
    }}
'''

field_setter_set_tpl = '''
    void set_{field_name}(std::set<std::shared_ptr<ObjectBase>> const &{field_name}_) {{
        this->{field_name} = {field_name}_;
    }}
    void add_{field_name}(std::shared_ptr<ObjectBase> const &{field_name}_) {{
        this->{field_name}.emplace({field_name}_);
    }}
'''

field_setter_dict_tpl = '''
    void set_{field_name}(std::map<{field_key_type}, std::shared_ptr<ObjectBase>> const &{field_name}_) {{
        this->{field_name} = {field_name}_;
    }}
    // FIXME: set a corresponding builder, rather than ObjectBase.
    void set_{field_name}({field_key_type} const &{field_name}_key_,
                           std::shared_ptr<ObjectBase> {field_name}_value_) {{
        this->{field_name}.emplace({field_name}_key_, {field_name}_value_);
    }}
    void remove_{field_name}({field_key_type} const &{field_name}_key_) {{
        this->{field_name}.erase({field_name}_key_);
    }}
'''


def codegen_field_setter(field_name, field_type, spec):
    if spec.is_meta:
        tpl = field_setter_meta_tpl
    if spec.is_plain:
        tpl = field_setter_plain_tpl
    if spec.is_list:
        tpl = field_setter_list_tpl
    if spec.is_dlist:
        tpl = field_setter_dlist_tpl
    if spec.is_set:
        tpl = field_setter_set_tpl
    if spec.is_dict:
        tpl = field_setter_dict_tpl
    if spec.is_dict:
        field_key_type = 'typename %s::key_type' % field_type
        field_value_type = 'typename %s::mapped_type' % field_type
    else:
        field_key_type = None
        field_value_type = None
    return tpl.format(
        field_name=field_name,
        field_type=field_type,
        field_key_type=field_key_type,
        field_value_type=field_value_type,
    )


get_assign_meta_tpl = '''
        this->set_{field_name}(__value.{field_name});'''

get_assign_plain_tpl = '''
        this->set_{field_name}(
            std::make_shared<typename std::decay<decltype(__value.{field_name})>::type>(
                __value.{field_name}));'''

get_assign_plain_star_tpl = '''
        this->set_{field_name}(__value.{field_name});'''

get_assign_sequence_tpl = '''
        for (auto const &__{field_name}_item: __value.{field_name}) {{
            this->add_{field_name}(
                std::make_shared<typename std::decay<decltype(__{field_name}_item)>::type>(
                    __{field_name}_item));
        }}'''

get_assign_sequence_star_tpl = '''
        for (auto const &__{field_name}_item: __value.{field_name}) {{
            this->add_{field_name}(__{field_name}_item);
        }}'''

get_assign_dlist_tpl = '''
        this->{field_name}.resize(__value.{field_name}.size());
        for (size_t __idx = 0; __idx < __value.{field_name}.size(); ++__idx) {{
            this->{field_name}[__idx].resize(__value.{field_name}[__idx].size());
            for (size_t __idy = 0; __idy < __value.{field_name}[__idx].size(); ++__idy) {{
                auto const &__{field_name}_item = __value.{field_name}[__idx][__idy];
                this->{field_name}[__idx][__idy] =
                    std::make_shared<typename std::decay<decltype(__{field_name}_item)>::type>(
                        __{field_name}_item));
            }}
        }}'''

get_assign_dlist_star_tpl = '''
        this->{field_name}.resize(__value.{field_name}.size());
        for (size_t __idx = 0; __idx < __value.{field_name}.size(); ++__idx) {{
            this->{field_name}[__idx].resize(__value.{field_name}[__idx].size());
            for (size_t __idy = 0; __idy < __value.{field_name}[__idx].size(); ++__idy) {{
                this->{field_name}[__idx][__idy] = __value.{field_name}[__idx][__idy];
            }}
        }}'''

get_assign_dict_tpl = '''
        for (auto const &__{field_name}_item_kv: __value.{field_name}) {{
            this->set_{field_name}(__{field_name}_item_kv.first,
                                   std::make_shared<typename std::decay<
                                        decltype(__{field_name}_item_kv.second)>::type>(
                                        __{field_name}_item_kv.second));
        }}'''

get_assign_dict_star_tpl = '''
        for (auto const &__{field_name}_item_kv: __value.{field_name}) {{
            this->set_{field_name}(__{field_name}_item_kv.first,
                                   __{field_name}_item_kv.second);
        }}'''


def codegen_field_get_assign(field_name, spec):
    if spec.is_meta:
        tpl = get_assign_meta_tpl
    if spec.is_plain:
        if spec.star:
            tpl = get_assign_plain_star_tpl
        else:
            tpl = get_assign_plain_tpl
    if spec.is_list or spec.is_set:
        if spec.star:
            tpl = get_assign_sequence_star_tpl
        else:
            tpl = get_assign_sequence_tpl
    if spec.is_dlist:
        if spec.star:
            tpl = get_assign_dlist_star_tpl
        else:
            tpl = get_assign_dlist_tpl
    if spec.is_dict:
        if spec.star:
            tpl = get_assign_dict_star_tpl
        else:
            tpl = get_assign_dict_tpl
    return tpl.format(field_name=field_name)


using_alias_tpl = '''
    // using {alias}
    {extent};'''


def codegen_using_alias(alias, extent):
    return using_alias_tpl.format(alias=alias, extent=extent)


post_construct_in_seal_tpl = '''
        // run `PostConstruct` to return a valid object
        __value->PostConstruct(__value->meta_);
'''


def codegen_base_builder(
    class_header,
    type_parameters,
    class_name,
    class_name_elaborated,
    fields,
    using_alias_values,
    has_post_ctor,
):
    declarations = []
    assignments = []
    get_and_assigns = []
    setters = []
    using_alias_statements = []

    # generate using alias
    for alias, extent in using_alias_values:
        using_alias_statements.append(codegen_using_alias(alias, extent))

    # core field assignment
    for field in fields:
        name = field.spelling
        spec = parse_codegen_spec_from_type(field)
        field_type = field.type.spelling

        # generate field declarations
        declarations.append(codegen_field_declare(name, field_type, spec))

        # generate field assignment
        assignments.append(codegen_field_assign(name, field_type, spec))

        # generate get-and-assign statements
        get_and_assigns.append(codegen_field_get_assign(name, spec))

        # generate field setter method
        setters.append(codegen_field_setter(name, field_type, spec))

    if has_post_ctor:
        post_ctor = post_construct_in_seal_tpl
    else:
        post_ctor = ''

    if type_parameters:
        type_params = '<' + ', '.join(type_parameters) + '>'
    else:
        type_params = ''

    code = base_builder_tpl.format(
        class_header=class_header,
        type_params=type_params,
        class_name=class_name,
        class_name_elaborated=class_name_elaborated,
        post_construct=post_ctor,
        setters=''.join(setters).strip(),
        assignments=''.join(assignments).strip(),
        get_and_assign=''.join(get_and_assigns).strip(),
        using_alias=''.join(using_alias_statements).strip(),
        fields_declares=''.join(declarations).strip(),
    )
    return code


distributed_getter_tpl = '''
    size_t size() const {{
        return this->{field_name}.size();
    }}

    {field_type}::value_type Get(const size_t index) const {{
        return this->{field_name}[index];
    }}

    ObjectMeta GetMeta(const size_t index) const {{
        return this->{field_name}[index]->meta();
    }}

    Tuple<{field_type}::value_type> const &GetAll() const {{
        return this->{field_name};
    }}

    template <typename T>
    size_t GetLocals(Tuple<std::shared_ptr<T>> &locals) const {{
        size_t __local_size = 0;
        for (auto const &__e: this->{field_name}) {{
            if (__e->IsLocal()) {{
                auto const __item = std::dynamic_pointer_cast<T>(__e);
                if (__item != nullptr) {{
                    locals.emplace_back(__item);
                    __local_size++;
                }}
            }}
        }}
        return __local_size;
    }}

    Tuple<{field_type}::value_type> GetLocals() const {{
        Tuple<{field_type}::value_type> __locals;
        for (auto const &__e: this->{field_name}) {{
            if (__e->IsLocal()) {{
                __locals.emplace_back(__e);
            }}
        }}
        return __locals;
    }}
'''


def codegen_distributed_getter(field):
    field_name = field.spelling
    field_type = field.type.spelling
    return distributed_getter_tpl.format(field_name=field_name, field_type=field_type)


streamable_tpl = '''
{class_header}
using {name}StreamBase = vineyard::Stream<{name_elaborated}>;
'''


def codegen_streamable_builder(class_header, name, name_elaborated):
    code = streamable_tpl.format(
        class_header=class_header, name=name, name_elaborated=name_elaborated
    )
    return code


def generate_inclusion(includes):
    code = []
    for inc in includes:
        code.append('#include <%s>' % inc.spelling)
    return '\n'.join(code)


def generate_create(header, name, name_elaborated):
    return codegen_create(header, name, name_elaborated)


def generate_create_meth(header, name, name_elaborated):
    return codegen_create(header, name, name_elaborated, meth=True)


def generate_construct(
    fields, header, name, name_elaborated, has_post_ctor, verbose=False
):
    if verbose:
        print('construct: ', name, [(n.type.spelling, n.spelling) for n in fields])
    return codegen_construct(header, name, name_elaborated, fields, has_post_ctor)


def generate_construct_meth(
    fields, header, name, name_elaborated, has_post_ctor, verbose=False
):
    if verbose:
        print('construct: ', name, [(n.type.spelling, n.spelling) for n in fields])
    return codegen_construct(
        header, name, name_elaborated, fields, has_post_ctor, meth=True
    )


def generate_base_builder(
    fields,
    using_alias_values,
    header,
    type_parameters,
    name,
    name_elaborated,
    has_post_ctor,
    verbose=False,
):
    if verbose:
        print('base_builder: ', name, [(n.type.spelling, n.spelling) for n in fields])
    return codegen_base_builder(
        header,
        type_parameters,
        name,
        name_elaborated,
        fields,
        using_alias_values,
        has_post_ctor,
    )


def generate_getter_for_distributed(field, verbose=False):
    if verbose:
        print('distributed: ', field.spelling)
    return codegen_distributed_getter(field)


def generate_streamable(header, name, name_elaborated, verbose=False):
    if verbose:
        print('streamable: ', name, name_elaborated)
    return codegen_streamable_builder(header, name, name_elaborated)


def codegen(  # pylint: disable=too-many-statements
    root_directory, content, to_reflect, source, target=None, verbose=False
):
    logging.info('Generating for %s ...', os.path.basename(source))

    filename, _ = os.path.splitext(source)

    if target is not None:
        generated_file_path = target
    else:
        generated_file_path = '%s%s' % (filename, '.vineyard.h')

    real_root_path = os.path.realpath(root_directory)
    real_generate_path = os.path.realpath(generated_file_path)
    if real_root_path in real_generate_path:
        macro_guard_base = real_generate_path[len(real_root_path) + 1 :]
    else:
        macro_guard_base = generated_file_path
    macro_guard = (
        macro_guard_base.upper().replace('.', '_').replace('/', '_').replace('-', '_')
    )

    with open(generated_file_path, 'w', encoding='utf-8') as fp:
        code_injections = []
        code_blocks = []

        for kind, namespaces, node in to_reflect:
            (
                fields,
                using_alias,
                type_parameters,
                first_member_offset,
                has_post_ctor,
            ) = find_fields(node)

            name, ts = check_class(node)
            members, _methods = split_members_and_methods(fields)

            # get extend of using A = B
            using_alias_values = [
                (n, content[t.start.offset : t.end.offset]) for (n, t) in using_alias
            ]

            # get extent of type parameters, since default value may involved.
            ts_names = [(t, k) for (t, _, k) in ts]  # without `typename`
            ts_name_values = [
                (content[t.start.offset : t.end.offset], k) for (_, t, k) in ts
            ]  # with `typename`

            name_elaborated = generate_template_type(name, ts_names, type_parameters)

            header = generate_template_header(ts_names, type_parameters)
            header_elaborated = generate_template_header(
                ts_name_values, type_parameters
            )

            meth_create = generate_create_meth(header, name, name_elaborated)
            meth_construct = generate_construct_meth(
                members, header, name, name_elaborated, has_post_ctor, verbose=verbose
            )
            inject_blocks = [meth_create, meth_construct]

            mb_distributed = find_distributed_field(members)
            if mb_distributed is not None:
                if kind == 'vineyard(streamable)':
                    raise ValueError(
                        'A stream cannot be a distributed object: %s' % name
                    )
                inject_blocks.append(
                    generate_getter_for_distributed(mb_distributed, verbose=verbose)
                )

            to_inject = '%s\n private:\n' % ('\n'.join(inject_blocks))
            code_injections.append((first_member_offset, to_inject))

            base_builder = generate_base_builder(
                members,
                using_alias_values,
                header_elaborated,
                type_parameters,
                name,
                name_elaborated,
                has_post_ctor,
                verbose=verbose,
            )
            code_blocks.append((namespaces, base_builder))

            if kind == 'vineyard(streamable)':
                streamable = generate_streamable(
                    header, name, name_elaborated, verbose=verbose
                )
                code_blocks.append((namespaces, streamable))

        fp.write('#ifndef %s\n' % macro_guard)
        fp.write('#define %s\n\n' % macro_guard)

        # FIXME print the content of the original file
        offset = 0
        for next_offset, injection in code_injections:
            fp.write(content[offset:next_offset])
            fp.write(injection)
            offset = next_offset
        fp.write(content[offset:])

        for namespaces, block in code_blocks:
            if namespaces is not None:
                fp.write('\n\n')
                for ns in namespaces:
                    fp.write('namespace %s {\n' % ns)

            # print the code block
            fp.write(block)

            if namespaces is not None:
                fp.write('\n\n')
                for ns in namespaces:
                    fp.write('}  // namespace %s\n' % ns)
                fp.write('\n\n')

        fp.write('\n#endif // %s\n' % macro_guard)
