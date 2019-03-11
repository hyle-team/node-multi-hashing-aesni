#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>
#include "multihashing.h"

extern "C" {
    #include "cryptonight.h"
    #include "cryptonight_light.h"
    #include "wild_keccak2.h"
}

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char* data, void* hint) {
  free(data);
}

using namespace node;
using namespace v8;
using namespace Nan;

NAN_METHOD(cryptonight) {
    bool fast = false;

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    if (info.Length() >= 2) {
        if(!info[1]->IsBoolean())
            return THROW_ERROR_EXCEPTION("Argument 2 should be a boolean");
        fast = info[1]->ToBoolean()->BooleanValue();
    }

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else
        cryptonight_hash(input, output, input_len);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

class CNAsyncWorker : public Nan::AsyncWorker{
    public:
        CNAsyncWorker(Nan::Callback *callback, char * input, uint32_t input_len)
            : Nan::AsyncWorker(callback), input(input), input_len(input_len){}
        ~CNAsyncWorker() {}

    void Execute () {
        cryptonight_hash(input, output, input_len);
      }

    void HandleOKCallback () {
        Nan::HandleScope scope;

        v8::Local<v8::Value> argv[] = {
            Nan::Null()
          , v8::Local<v8::Value>(Nan::CopyBuffer(output, 32).ToLocalChecked())
        };

        callback->Call(2, argv);
      }

    private:
        uint32_t input_len;
        char * input;
        char output[32];
};

NAN_METHOD(CNAsync) {

    if (info.Length() != 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = info[0]->ToObject();
    Callback *callback = new Nan::Callback(info[1].As<v8::Function>());

    char * input = Buffer::Data(target);
    uint32_t input_len = Buffer::Length(target);

    Nan::AsyncQueueWorker(new CNAsyncWorker(callback, input, input_len));
}

class CNLAsyncWorker : public Nan::AsyncWorker{
    public:
        CNLAsyncWorker(Nan::Callback *callback, char * input, uint32_t input_len)
            : Nan::AsyncWorker(callback), input(input), input_len(input_len){}
        ~CNLAsyncWorker() {}

    void Execute () {
        cryptonight_light_hash(input, output, input_len);
      }

    void HandleOKCallback () {
        Nan::HandleScope scope;

        v8::Local<v8::Value> argv[] = {
            Nan::Null()
          , v8::Local<v8::Value>(Nan::CopyBuffer(output, 32).ToLocalChecked())
        };

        callback->Call(2, argv);
      }

    private:
        uint32_t input_len;
        char * input;
        char output[32];
};

NAN_METHOD(CNLAsync) {

    if (info.Length() != 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = info[0]->ToObject();
    Callback *callback = new Nan::Callback(info[1].As<v8::Function>());

    char * input = Buffer::Data(target);
    uint32_t input_len = Buffer::Length(target);

    Nan::AsyncQueueWorker(new CNLAsyncWorker(callback, input, input_len));
}

NAN_METHOD(cryptonight_light) {

    bool fast = false;

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    if (info.Length() >= 2) {
        if(!info[1]->IsBoolean())
            return THROW_ERROR_EXCEPTION("Argument 2 should be a boolean");
        fast = info[1]->ToBoolean()->BooleanValue();
    }

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_light_fast_hash(input, output, input_len);
    else
        cryptonight_light_hash(input, output, input_len);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

NAN_METHOD(wildkeccak2) {
    if (info.Length() != 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    char * input = Buffer::Data(target);
    uint32_t input_len = Buffer::Length(target);

    Local<Object> scratchpad = info[1]->ToObject();

    if(!Buffer::HasInstance(scratchpad))
        return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");

    char * spad = Buffer::Data(scratchpad);
    uint64_t spad_len = Buffer::Length(scratchpad);

    char output[32];

    wildkeccak2_hash(input, input_len, spad, spad_len, output);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

NAN_METHOD(wildkeccak2_scratchpad) {
    if (info.Length() != 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> seed = info[0]->ToObject();

    if(!Buffer::HasInstance(seed))
        return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    char * s = Buffer::Data(seed);

    if(!info[1]->IsInt32())
        return THROW_ERROR_EXCEPTION("Argument 2 should be an int32");
    int height = info[1]->IntegerValue();

    uint64_t result_len = wildkeccak2_scratchpad_size(height);

    char *output = (char *) malloc((size_t) result_len);

    wildkeccak2_generate_scratchpad(s, output, height);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, result_len).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );

    free(output);
}

NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, Nan::New("CNAsync").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(CNAsync)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_light").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_light)).ToLocalChecked());
    Nan::Set(target, Nan::New("CNLAsync").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(CNAsync)).ToLocalChecked());
    Nan::Set(target, Nan::New("wildkeccak2").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(wildkeccak2)).ToLocalChecked());
    Nan::Set(target, Nan::New("wildkeccak2_scratchpad").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(wildkeccak2_scratchpad)).ToLocalChecked());
}

NODE_MODULE(multihashing, init)
