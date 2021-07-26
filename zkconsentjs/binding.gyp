{
  "targets": [
    {
      "target_name": "nodegw",

      "sources": [ "src/snark2node.cc", 
                   "src/snark_node_obj.cpp" ],

      "libraries": ["/usr/local/lib/libsnarkhlp.so"], 

      "include_dirs" : [ 
        "/usr/local/include",
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "defines": [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ]
    }
  ]
}