{
  "targets": [
    {
      "target_name": "nodegw",
      "sources": [ "src/snark2node.cc" ],
      "libraries": ["<!(pwd)/../build/bin/libsnarkhlp.a"],      
      "include_dirs" : [ "<!(pwd)/../build/include" ]
    }
  ]
}