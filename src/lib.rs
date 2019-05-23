#[macro_use]
extern crate napi_rs as napi;

use std::ops::Deref;
use std::str;

use napi::{
  Any, Buffer, Env, Error, Function, Object, Property, Result, Status, String as JsString, Value,
};
use ring::digest;

const ALGORITHM_NAME: &'static str = "algorithm";

register_module!(crypto, init);

fn init<'env>(
  env: &'env Env,
  exports: &'env mut Value<'env, Object>,
) -> Result<Option<Value<'env, Object>>> {
  exports.set_named_property(
    "createHasher",
    env.create_function("createHasher", callback!(create_hasher)),
  )?;
  Ok(None)
}

fn create_hasher<'a>(
  env: &'a Env,
  _this: Value<'a, Any>,
  _args: &[Value<'a, Any>],
) -> Result<Option<Value<'a, Function>>> {
  let digest_property = Property::new("digest");
  let digest_property = digest_property.with_method(callback!(digest));
  Ok(Some(env.define_class(
    "Hasher",
    callback!(hasher_constructor),
    vec![digest_property],
  )))
}

fn hasher_constructor<'a>(
  env: &'a Env,
  mut this: Value<'a, Object>,
  args: &[Value<'a, Any>],
) -> Result<Option<Value<'a, Any>>> {
  let algorithm = args[0];
  let algorithm = algorithm.coerce_to_string()?;
  let algorithm_u16_arr: Vec<u16> = algorithm.into();
  let algorithm = String::from_utf16(algorithm_u16_arr.as_ref())
    .map_err(|_e| Error::new(Status::StringExpected))?;
  this.set_named_property(ALGORITHM_NAME, env.create_string(algorithm.as_str()))?;
  Ok(Some(Value::<Any>::from_raw(env, this.into_raw())))
}

fn digest<'a>(
  env: &'a Env,
  this: Value<'a, Any>,
  args: &[Value<'a, Any>],
) -> Result<Option<Value<'a, JsString>>> {
  let this: Value<Object> = Value::from_raw(env, this.into_raw());
  let algorithm: Value<JsString> = this.get_named_property(ALGORITHM_NAME)?;
  let algorithm = get_algorithm(
    str::from_utf8(algorithm.deref()).map_err(|_e| Error::new(Status::StringExpected))?,
  )?;
  let mut ctx = digest::Context::new(algorithm);
  for arg in args {
    let buffer = arg.try_into::<Buffer>()?;
    ctx.update(buffer.deref());
  }
  let result = ctx.finish();
  let hex_str = hex::encode(result.as_ref());
  Ok(Some(env.create_string(hex_str.as_str())))
}

fn get_algorithm(algorithm: &str) -> Result<&'static digest::Algorithm> {
  let algorithm = match algorithm {
    "sha256" => &digest::SHA256,
    "sha1" => &digest::SHA1,
    "sha384" => &digest::SHA384,
    "sha512" => &digest::SHA512,
    _ => return Err(Error::new(Status::InvalidArg)),
  };
  Ok(algorithm)
}
