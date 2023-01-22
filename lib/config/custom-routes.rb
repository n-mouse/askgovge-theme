# -*- encoding : utf-8 -*-
# Here you can override or add to the pages in the core website

Rails.application.routes.draw do
  match '/about' => 'help#intro',
        :as => :help_intro,
        :via => :get
  match '/help/publicinfo' => 'help#publicinfo',
        :as => :help_publicinfo,
        :via => :get
end
