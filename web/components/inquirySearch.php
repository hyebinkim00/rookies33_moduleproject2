<div class="inquiry-search-wrap">
    <form method="GET" class="inquiry-search"> 
        <select name="type"> 
            <option value="title">제목</option> 
            <option value="content">내용</option> 
            <option value="title_content">제목 + 내용</option> 
        </select> 
 
        <input type="text" name="keyword" placeholder="검색어를 입력해주세요."> 
        <button type="submit">검색</button> 
    </form>

    <div id="search-result-text"></div>
</div>

<script> 
    const urlParams = new URLSearchParams(window.location.search); 
    const keyword = urlParams.get('keyword'); 
 
    if (keyword) { 
        document.getElementById('search-result-text').innerHTML = 
            `"<span>${keyword}</span>" 검색 결과`; 
    } 
</script>