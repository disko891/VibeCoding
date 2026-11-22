// 자주 바뀌지 않는 조회 결과를 잠깐 메모리에 저장해서 DB 호출을 줄인다
// - 데이터가 바뀌는 요청(POST)이 끝나면 app.js에서 전부 비움 → 수정 내용은 바로 반영됨
// - 동시에 같은 키를 요청하면 쿼리는 한 번만 실행 (Promise 공유)
// - pm2를 cluster 모드(여러 프로세스)로 돌리면 프로세스마다 따로 저장되므로 fork 모드(기본)로 실행할 것

const store = new Map(); // key -> { promise, expires }

function cached(key, ttlMs, loader) {
  const hit = store.get(key);
  if (hit && hit.expires > Date.now()) return hit.promise;

  const promise = Promise.resolve().then(loader);
  store.set(key, { promise, expires: Date.now() + ttlMs });
  // 실패한 결과는 저장하지 않음
  promise.catch(() => {
    if (store.get(key) && store.get(key).promise === promise) store.delete(key);
  });
  return promise;
}

function clear() {
  store.clear();
}

module.exports = { cached, clear };
