#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdlib.h>
#include "sha3.h"

static PyObject *sha3_error;

static PyObject *py_sha3_hash(PyObject *self, PyObject *args) {
    const char *data;
    Py_ssize_t len;
    int bit_len;
    
    if (!PyArg_ParseTuple(args, "s#i", &data, &len, &bit_len)) {
        return NULL;
    }
    
    if (bit_len != 224 && bit_len != 256 && bit_len != 384 && bit_len != 512) {
        PyErr_SetString(sha3_error, "Invalid hash bit length (must be 224, 256, 384, or 512)");
        return NULL;
    }
    
    int hash_len = bit_len / 8;
    sha3_byte_t *hash = malloc(hash_len);
    if (!hash) {
        return PyErr_NoMemory();
    }
    
    sha3_hash((const sha3_byte_t *)data, (sha3_size_t)len, (sha3_size_t)bit_len, hash);
    
    PyObject *result = PyBytes_FromStringAndSize((const char *)hash, hash_len);
    free(hash);
    return result;
}

static PyObject *py_hash_224(PyObject *self, PyObject *args) {
    const char *data;
    Py_ssize_t len;
    
    if (!PyArg_ParseTuple(args, "s#", &data, &len)) {
        return NULL;
    }
    
    sha3_byte_t hash[28];
    sha3_224((const sha3_byte_t *)data, (sha3_size_t)len, hash);
    
    return PyBytes_FromStringAndSize((const char *)hash, 28);
}

static PyObject *py_hash_256(PyObject *self, PyObject *args) {
    const char *data;
    Py_ssize_t len;
    
    if (!PyArg_ParseTuple(args, "s#", &data, &len)) {
        return NULL;
    }
    
    sha3_byte_t hash[32];
    sha3_256((const sha3_byte_t *)data, (sha3_size_t)len, hash);
    
    return PyBytes_FromStringAndSize((const char *)hash, 32);
}

static PyObject *py_hash_384(PyObject *self, PyObject *args) {
    const char *data;
    Py_ssize_t len;
    
    if (!PyArg_ParseTuple(args, "s#", &data, &len)) {
        return NULL;
    }
    
    sha3_byte_t hash[48];
    sha3_384((const sha3_byte_t *)data, (sha3_size_t)len, hash);
    
    return PyBytes_FromStringAndSize((const char *)hash, 48);
}

static PyObject *py_hash_512(PyObject *self, PyObject *args) {
    const char *data;
    Py_ssize_t len;
    
    if (!PyArg_ParseTuple(args, "s#", &data, &len)) {
        return NULL;
    }
    
    sha3_byte_t hash[64];
    sha3_512((const sha3_byte_t *)data, (sha3_size_t)len, hash);
    
    return PyBytes_FromStringAndSize((const char *)hash, 64);
}

static PyMethodDef Sha3Methods[] = {
    {"sha3_hash", py_sha3_hash, METH_VARARGS, "Generic SHA-3 hash function"},
    {"sha3_224", py_hash_224, METH_VARARGS, "SHA3-224 hash"},
    {"sha3_256", py_hash_256, METH_VARARGS, "SHA3-256 hash"},
    {"sha3_384", py_hash_384, METH_VARARGS, "SHA3-384 hash"},
    {"sha3_512", py_hash_512, METH_VARARGS, "SHA3-512 hash"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef sha3module = {
    PyModuleDef_HEAD_INIT,
    "sha3_c",
    "Python bindings for SHA-3 C implementation",
    -1,
    Sha3Methods
};

PyMODINIT_FUNC PyInit_sha3_c(void) {
    PyObject *module;
    
    module = PyModule_Create(&sha3module);
    if (module == NULL) {
        return NULL;
    }
    
    sha3_error = PyErr_NewException("sha3_c.error", NULL, NULL);
    Py_INCREF(sha3_error);
    PyModule_AddObject(module, "error", sha3_error);
    
    return module;
}
