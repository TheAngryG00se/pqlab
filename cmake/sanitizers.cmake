if(PQ_SANITIZE)
  add_compile_options(-fsanitize=${PQ_SANITIZE} -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=${PQ_SANITIZE})
endif()
