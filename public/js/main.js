// 삭제 같은 폼은 data-confirm 넣어두면 확인창 띄움
document.querySelectorAll('form[data-confirm]').forEach((form) => {
  form.addEventListener('submit', (e) => {
    if (!confirm(form.dataset.confirm)) e.preventDefault();
  });
});

// 회원가입: 관리자 계정 고르면 관리자 암호 칸 보이기
const adminBox = document.getElementById('adminCodeBox');
if (adminBox) {
  const sync = () => {
    const on = document.getElementById('role_admin').checked;
    adminBox.hidden = !on;
    document.getElementById('admin_code').required = on;
  };
  document.querySelectorAll('input[name="role"]').forEach((r) => r.addEventListener('change', sync));
  sync();
}

// 테이블 행 클릭하면 상세로 이동
document.querySelectorAll('tr.row-link').forEach((tr) => {
  tr.addEventListener('click', (e) => {
    if (e.target.closest('a, button, form')) return;
    location.href = tr.dataset.href;
  });
});
