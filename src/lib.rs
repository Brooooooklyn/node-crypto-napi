#[macro_use]
extern crate napi_rs as napi;

use std::mem;

use napi::{Any, Buffer, Env, Error, Function, Number, Object, Property, Result, Status, Value, Undefined};
use ring::digest;

const PTR_NAME: &'static str = "raw_ptr";

struct Ctx<'a>(&'a mut digest::Context);

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
  let update_property = Property::new("update");
  let update_property = update_property.with_method(callback!(update));
  Ok(Some(env.define_class(
    "Hasher",
    callback!(hasher_constructor),
    vec![update_property],
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
  let algorithm = match algorithm.as_str() {
    "sha256" => &digest::SHA256,
    "sha1" => &digest::SHA1,
    "sha384" => &digest::SHA384,
    "sha512" => &digest::SHA512,
    _ => return Err(Error::new(Status::InvalidArg)),
  };
  let mut raw_ctx = digest::Context::new(&algorithm);
  let ctx = Ctx(&mut raw_ctx);
  let ctx = Box::new(ctx);
  let ptr = Box::into_raw(ctx);
  this.set_named_property(PTR_NAME, env.create_int64(ptr as i64))?;
  Ok(Some(Value::<Any>::from_raw(env, this.into_raw())))
}

fn update<'a>(
  env: &'a Env,
  this: Value<'a, Any>,
  args: &[Value<'a, Any>],
) -> Result<Option<Value<'a, Undefined>>> {
  let this: Value<Object> = Value::from_raw(env, this.into_raw());
  let ptr: Value<Number> = this.get_named_property(PTR_NAME)?;
  let ref_ptr: i64  = ptr.into();
  let ctx = unsafe { mem::transmute::<u64, &mut Ctx<'a>>(ref_ptr as u64) };
  let ctx: &mut Ctx<'a> = ctx;
  let data = args[0];
  let data: Value<Buffer> = Value::from_raw(env, data.into_raw());
  ctx.0.update(&data);
  Ok(Some(env.get_undefined()))
}
