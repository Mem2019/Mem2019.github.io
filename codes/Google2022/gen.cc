#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "include/libplatform/libplatform.h"
#include "include/v8-context.h"
#include "include/v8-initialization.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-primitive.h"
#include "include/v8-script.h"
#include "src/api/api-inl.h"
#include "src/base/platform/platform.h"
#include "src/execution/isolate-inl.h"
#include "src/objects/instance-type.h"
#include "src/roots/roots.h"
#include "src/snapshot/code-serializer.h"

char input_data[65536] = {0};

void run(int argc, char* argv[]) {
  v8::V8::InitializeICUDefaultLocation(argv[0]);
  v8::V8::InitializeExternalStartupData(argv[0]);
  std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  v8::V8::Initialize();
  v8::V8::SetFlagsFromCommandLine(&argc, argv, true);

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator =
      v8::ArrayBuffer::Allocator::NewDefaultAllocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);

  const v8::ScriptCompiler::CachedData* cached_data;

  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::String> source_string;
    if (!v8::String::NewFromUtf8(isolate, input_data).ToLocal(&source_string)) {
      printf("Failed loading source\n");
      return;
    }
    v8::Local<v8::String> origin_string =
      v8::String::NewFromUtf8Literal(isolate, "origin");
    v8::ScriptOrigin script_origin(isolate, origin_string);
    v8::ScriptCompiler::Source source(source_string, script_origin);

    printf("Loading\n");
    v8::Local<v8::Script> script =
        v8::ScriptCompiler::Compile(context, &source)
            .ToLocalChecked();
    printf("Running\n");
    script->Run(context).ToLocalChecked();
    cached_data = v8::ScriptCompiler::CreateCodeCache(script->GetUnboundScript());
    if (cached_data == nullptr) {
      printf("No cached data is generated.\n");
      return;
    }
    if (cached_data->rejected) {
      printf("Code is rejected.\n");
    }
  }

  isolate->Dispose();
  v8::V8::Dispose();
  v8::V8::DisposePlatform();
  delete create_params.array_buffer_allocator;

  uint8_t* data = new uint8_t[cached_data->length];
  memcpy(data, cached_data->data, cached_data->length);
  *(uint32_t*)(data + 8) = 0; // set the hash to 0, so that code will not be rejected

  FILE* output_file = fopen("blob.bin", "wb");
  size_t r = fwrite(data, 1, cached_data->length, output_file);
  if (static_cast<int>(r) != cached_data->length)
    printf("I/O error for fwrite.\n");
  fclose(output_file);
  delete[] data;
}

int main(int argc, char* argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  if (argc < 2) {
    printf("No input file.\n");
    return -1;
  }

  FILE *input_file = fopen(argv[1], "rb");
  fseek(input_file, 0, SEEK_END);
  size_t input_size = ftell(input_file);
  fseek(input_file, 0, SEEK_SET);
  if (input_size > 65535) {
    printf("Input too big.\n");
    return -1;
  }
  if (fread(input_data, 1, input_size, input_file) != input_size) {
    printf("I/O error.\n");
    return -1;
  }
  fclose(input_file);

  run(argc, argv);
  return 0;
}
